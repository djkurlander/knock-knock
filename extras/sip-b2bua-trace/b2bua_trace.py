#!/usr/bin/env python3
"""Analyze the B2BUA trace log: call lifecycle, completions, holds, DTMF.

Reads the durable trace file written by sip_b2bua.py's source-tee
(`PBX_TRACE_FILE`, default `data/b2bua_trace.log`) — preferred over the systemd
journal, which is a size-capped ring buffer and only forwards lines matching its
`*TRACE` passthrough. Each record is `<ISO-ts> SIPTRACE component=b2bua id=… stage=… …`.

Bridges are reconstructed by `id`. Each bridge's `rtp_dump_armed` line names its
.rtp dump, so cross-referencing the dump dir (default `data/rtp_dumps`) tells us
whether the attacker actually *sent* inbound media on that call (file present and
non-empty) — the silent-vs-engaged distinction.

Modes:
    (default)       summary: outcome breakdown + completed/held destinations
    --completions   per-bridge list of bridges that ACKed / held to cap / BYE'd
    --dtmf          SIP-INFO/DTMF captures (stage=attacker_info)
    --listeners     SDP media reachability + listener verdict, rolled up by actor

The listener verdict fuses three signals the B2BUA now emits per bridge: the
advertised RTP endpoint (stage=sdp_media: where the bot said to send audio, and
its reachability class), the live ICMP feedback (stage=rtp_unreachable: our relay
bounced off a closed port), and any positive media (inbound RTP dump / DTMF).

Usage:
    python extras/sip-b2bua-trace/b2bua_trace.py
    python extras/sip-b2bua-trace/b2bua_trace.py --completions --number 541139876436
    python extras/sip-b2bua-trace/b2bua_trace.py --dtmf
    python extras/sip-b2bua-trace/b2bua_trace.py --listeners --number 12022234942
    cat data/b2bua_trace.log | python extras/sip-b2bua-trace/b2bua_trace.py -
"""
import argparse
import collections
import os
import re
import sys

ID = re.compile(r'\bid=(\w+)')
ST = re.compile(r'\bstage=(\w+)')
FILE = re.compile(r"file='([^']+)'")
AGE = re.compile(r'\bage=([\d.]+)')
CAP = re.compile(r'\bcap=([\d.]+)')
RSN = re.compile(r"reason='([^']*)'")
DIGIT = re.compile(r"\bdigit=(?:'([^']*)'|None)")
TS = re.compile(r'^(\S+)\s')
CIP = re.compile(r"c_ip='([^']*)'")
PORTN = re.compile(r'\bport=(\d+)')
CLS = re.compile(r"cls='([^']*)'")
SIGM = re.compile(r'\bsig_match=(\w+)')


def parse(lines):
    """Return (bridges_by_id, setup_failures). setup_failed lines carry ip+err
    but no id, so they're collected separately."""
    br = {}
    setup_failed = []
    for line in lines:
        mst = ST.search(line)
        if not mst:
            continue
        stage = mst.group(1)
        if stage == 'setup_failed':
            mip = re.search(r"ip='([^']+)'", line)
            setup_failed.append(mip.group(1) if mip else '?')
            continue
        mid = ID.search(line)
        if not mid:
            continue
        d = br.setdefault(mid.group(1), {'stages': set(), 'dtmf': []})
        d['stages'].add(stage)
        mts = TS.match(line)
        if mts:
            d.setdefault('first_ts', mts.group(1))
            d['last_ts'] = mts.group(1)
        if stage == 'rtp_dump_armed':
            mf = FILE.search(line)
            if mf:
                d['fname'] = mf.group(1)
                p = mf.group(1).split('-')
                if len(p) >= 4:
                    d['ip'], d['num'] = p[1], p[3]
        elif stage == 'closed':
            a, r = AGE.search(line), RSN.search(line)
            if a:
                d['age'] = float(a.group(1))
            if r:
                d['reason'] = r.group(1)
        elif stage == 'timeout':
            c = CAP.search(line)
            if c:
                d['cap'] = float(c.group(1))
        elif stage == 'attacker_info':
            m = DIGIT.search(line)
            d['dtmf'].append(m.group(1) if (m and m.group(1)) else 'none')
        elif stage == 'sdp_media':
            mc, mp, mcl, msm = (CIP.search(line), PORTN.search(line),
                                CLS.search(line), SIGM.search(line))
            d['sdp_ip'] = mc.group(1) if mc else None
            d['sdp_port'] = mp.group(1) if mp else None
            d['sdp_cls'] = mcl.group(1) if mcl else None
            d['sig_match'] = msm.group(1) if msm else None
        # rtp_unreachable carries no extra fields we need beyond its presence in
        # d['stages'] (added generically above); the verdict checks for it there.
    return br, setup_failed


def outcome(d):
    s = d['stages']
    if 'timeout' in s:
        return 'held_to_cap'
    if 'attacker_ack' in s and 'attacker_bye' in s:
        return 'ack_then_bye'
    if 'attacker_bye' in s:
        return 'bye_no_ack'          # media-probe style (e.g. ab00day): BYE without ACK
    if 'attacker_ack' in s:
        return 'acked_other'
    if 'attacker_no_ack' in s:
        return 'no_ack'              # answer-supervision then abandoned
    if 'attacker_cancel' in s:
        return 'cancel'
    return 'other'


COMPLETED = {'held_to_cap', 'ack_then_bye', 'bye_no_ack', 'acked_other'}


def media_size(d, dumps):
    fn = d.get('fname')
    return dumps.get(fn) if fn in dumps else None


def hold(d):
    return d.get('cap') or d.get('age') or 0.0


ENGAGED_MIN_BYTES = 400  # ≥~2 G.711 packets of inbound RTP ⇒ a real, active media
                         # stack — filters 1-packet probe noise from 'engaged'.

VERDICT_DESC = {
    'listener':     'engaged: sent RTP/DTMF — our audio is delivered',
    'possible':     'public RTP endpoint, silent — could be receiving',
    'not-listener': 'unroutable endpoint or ICMP port-unreachable',
    'unknown':      'no sdp_media line (pre-instrumentation bridge)',
}


def listener_verdict(d, dumps):
    """Could the callee/bait audio we relay actually reach a consumer on this bridge?
    Precedence (strongest evidence wins):
      listener      positive media: it sent us sustained RTP, or DTMF. Even behind a
                    private SDP the B2BUA latches onto the real RTP source, so audio
                    is delivered there.
      not-listener  our relay bounced off a closed port (ICMP 3/3), OR it advertised
                    an unroutable media endpoint (private/absent/…) and sent nothing
                    to latch onto.
      possible      advertised a real public RTP endpoint, no bounce, but stayed
                    silent — it *could* be receiving, unprovable from our side.
      unknown       no sdp_media line (pre-instrumentation bridge)."""
    mb = media_size(d, dumps) or 0
    if mb >= ENGAGED_MIN_BYTES or d['dtmf']:
        return 'listener'
    if 'rtp_unreachable' in d['stages']:
        return 'not-listener'
    cls = d.get('sdp_cls')
    if cls is None:
        return 'unknown'
    if cls == 'global':
        return 'possible'
    return 'not-listener'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?', default='data/b2bua_trace.log',
                    help='trace file (default data/b2bua_trace.log), or - for stdin')
    ap.add_argument('--media-dir', default='data/rtp_dumps',
                    help='RTP dump dir for media cross-reference (default data/rtp_dumps)')
    ap.add_argument('--completions', action='store_true',
                    help='list bridges that ACKed / held / BYE\'d (with media + DTMF)')
    ap.add_argument('--dtmf', action='store_true', help='list SIP-INFO/DTMF captures')
    ap.add_argument('--listeners', action='store_true',
                    help='SDP media reachability + listener verdict, rolled up by actor')
    ap.add_argument('--number', help='filter to a dialed number (digits, no +)')
    ap.add_argument('--ip', help='filter to a source IP')
    ap.add_argument('--top', type=int, default=15, help='top-N rows (default 15)')
    args = ap.parse_args(argv)

    src = sys.stdin if args.file == '-' else open(args.file)
    br, setup_failed = parse(src)
    if src is not sys.stdin:
        src.close()

    dumps = {}
    if os.path.isdir(args.media_dir):
        dumps = {f: os.path.getsize(os.path.join(args.media_dir, f))
                 for f in os.listdir(args.media_dir)}

    items = list(br.items())
    if args.number:
        items = [(i, d) for i, d in items if d.get('num') == args.number]
    if args.ip:
        items = [(i, d) for i, d in items if d.get('ip') == args.ip]

    if args.dtmf:
        hits = [(i, d) for i, d in items if d['dtmf']]
        print(f"SIP-INFO/DTMF captures (stage=attacker_info): {len(hits)} bridge(s)")
        for i, d in hits:
            print(f"  {d.get('last_ts','?')}  ip={d.get('ip','?'):16} num=+{d.get('num','?')}  "
                  f"digits={d['dtmf']}")
        return 0

    if args.completions:
        comp = sorted(((i, d) for i, d in items if outcome(d) in COMPLETED),
                      key=lambda kv: -hold(kv[1]))
        print(f"completed/held bridges: {len(comp)}")
        for i, d in comp[:args.top if args.top else len(comp)]:
            mb = media_size(d, dumps)
            media = f"{mb}B" if mb else "silent"
            tag = f"TIMEOUT {d['cap']}s" if d.get('cap') else f"{d.get('age','?')}s"
            dt = f" dtmf={d['dtmf']}" if d['dtmf'] else ""
            print(f"  {d.get('last_ts','?')}  ip={d.get('ip','?'):16} num=+{d.get('num','?'):14} "
                  f"{outcome(d):13} hold={tag:14} media={media}{dt} "
                  f"listener={listener_verdict(d, dumps)}")
        return 0

    if args.listeners:
        med = sum(1 for _, d in items if 'sdp_media' in d['stages'])
        print(f"listener analysis: {len(items)} bridge(s) in window; "
              f"{med} carry sdp_media instrumentation")
        tally = collections.Counter(listener_verdict(d, dumps) for _, d in items)
        print("\nverdict tally (all bridges in window):")
        for v in ('listener', 'possible', 'not-listener', 'unknown'):
            if tally.get(v):
                print(f"  {v:13} {tally[v]:6}   {VERDICT_DESC[v]}")
        # Per-actor roll-up of everything we can actually verdict (drop the 'unknown'
        # pre-instrumentation tail so the table isn't flooded). Includes media-engaged
        # actors (no sdp_media but non-empty RTP dump → 'listener') alongside the
        # sdp_media reachability rows; cls/addr show '-' where there's no SDP line.
        groups = collections.defaultdict(list)
        for _, d in items:
            if listener_verdict(d, dumps) != 'unknown':
                groups[(d.get('ip'), d.get('num'))].append(d)
        rows = []
        for (ip, num), ds in groups.items():
            vs = collections.Counter(listener_verdict(x, dumps) for x in ds)
            # Headline = the actor's dominant verdict; the L/P/N column keeps the
            # minority detail (e.g. one stray-RTP bridge among many not-listeners).
            headline = vs.most_common(1)[0][0]
            cls_c = collections.Counter(x['sdp_cls'] for x in ds if x.get('sdp_cls'))
            cls = cls_c.most_common(1)[0][0] if cls_c else '-'
            addr_c = collections.Counter(f"{x['sdp_ip']}:{x['sdp_port']}"
                                         for x in ds if x.get('sdp_ip'))
            addr = addr_c.most_common(1)[0][0] if addr_c else '-'
            unreach = sum(1 for x in ds if 'rtp_unreachable' in x['stages'])
            rows.append((len(ds), ip, num, headline, cls, addr, vs, unreach))
        print(f"\nby source IP → destination (verdicted bridges), top {args.top}:")
        for n, ip, num, headline, cls, addr, vs, unreach in \
                sorted(rows, key=lambda r: -r[0])[:args.top]:
            lpn = f"L{vs.get('listener',0)}/P{vs.get('possible',0)}/N{vs.get('not-listener',0)}"
            print(f"  ip={ip or '?':16} num=+{num or '?':14} bridges={n:4} "
                  f"{headline:13} cls={cls:11} addr={addr:21} {lpn:11} "
                  f"unreach={unreach}")
        return 0

    # default summary
    tss = sorted(d.get('first_ts', '') for _, d in items if d.get('first_ts'))
    print(f"window: {tss[0] if tss else '?'} → {tss[-1] if tss else '?'}")
    print(f"bridges: {len(items)}   setup_failed (no bridge): {len(setup_failed)}")
    if setup_failed:
        top = collections.Counter(setup_failed).most_common(3)
        print("  top setup_failed IPs: " + ", ".join(f"{ip}×{n}" for ip, n in top))
    print("\noutcomes:")
    oc = collections.Counter(outcome(d) for _, d in items)
    for o, c in oc.most_common():
        print(f"  {o:13} {c:6}")
    print("\ncompleted/held by destination (media-sent shown):")
    by_num = collections.defaultdict(lambda: [0, 0, 0.0])  # count, media-sent, max-hold
    for _, d in items:
        if outcome(d) in COMPLETED:
            k = '+' + (d.get('num') or '?')
            by_num[k][0] += 1
            by_num[k][1] += 1 if media_size(d, dumps) else 0
            by_num[k][2] = max(by_num[k][2], hold(d))
    for k, (c, m, mx) in sorted(by_num.items(), key=lambda kv: -kv[1][0])[:args.top]:
        print(f"  {k:16} bridges={c:4} media-sent={m:3} max-hold={mx:.0f}s")
    lt = collections.Counter(listener_verdict(d, dumps) for _, d in items)
    if any(v != 'unknown' for v in lt):
        print("\nlistener verdict (sdp_media instrumentation):")
        for v in ('listener', 'possible', 'not-listener', 'unknown'):
            if lt.get(v):
                print(f"  {v:13} {lt[v]:6}")
        print("  (run with --listeners for the per-actor roll-up)")
    dtmf_total = sum(len(d['dtmf']) for _, d in items)
    if dtmf_total:
        print(f"\nSIP-INFO/DTMF events: {dtmf_total} (run with --dtmf for detail)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
