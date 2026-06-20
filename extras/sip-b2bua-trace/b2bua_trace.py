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
    --listeners     two-axis media analysis (recv × sent), rolled up by actor

The two axes are kept separate (never collapsed into one verdict, which would hide
a bot that is reachable AND engaged — the strongest "may have listened" case):
  recv (downlink — the 'listened' axis): could the callee audio we relay reach them?
        reachable (stage=sdp_media cls=global + no stage=rtp_unreachable bounce) /
        unreachable (bounce, or private/unroutable advertised addr) / unknown (no sdp_media)
  sent (uplink): did they stream RTP/DTMF to us? engaged / silent — proves an active
        media stack, but says nothing about the downlink.

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

# Two orthogonal axes per bridge — never collapse them into one label, or an actor
# that is reachable on the downlink AND streaming on the uplink (the strongest
# "may have listened" candidate) gets hidden behind whichever axis is checked first.
RECV_DESC = {
    'reachable':   'public RTP endpoint, no bounce — our callee audio could land',
    'unreachable': 'ICMP port-unreachable, or private/unroutable advertised addr',
    'unknown':     'no sdp_media line (pre-instrumentation bridge)',
}
SENT_DESC = {
    'engaged': 'streamed RTP/DTMF to us — an active media stack',
    'silent':  'sent us no media',
}


def recv_status(d):
    """Downlink: could the callee/bait audio we relay reach a consumer on this bridge?
    This is the axis that actually bears on 'did they listen'. Independent of whether
    the bot sent us anything."""
    cls = d.get('sdp_cls')
    if cls is None:
        return 'unknown'                       # no sdp_media — not evaluable
    if 'rtp_unreachable' in d['stages']:
        return 'unreachable'                   # we relayed audio there, it bounced
    if cls == 'global':
        return 'reachable'                     # routable public addr, no bounce seen
    return 'unreachable'                        # private/unspecified/absent/… — can't land


def sent_status(d, dumps):
    """Uplink: did the bot stream media to us? Proves an active media stack, but says
    nothing about whether it received our downlink — a different pipe."""
    mb = media_size(d, dumps) or 0
    return 'engaged' if (mb >= ENGAGED_MIN_BYTES or d['dtmf']) else 'silent'


def may_have_listened(d):
    """The question of interest: could our callee audio have reached them? = downlink
    reachable, regardless of uplink. (reachable+engaged is the strongest such case.)"""
    return recv_status(d) == 'reachable'


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
                    help='two-axis media analysis (recv downlink × sent uplink), by actor')
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
                  f"recv={recv_status(d)} sent={sent_status(d, dumps)}")
        return 0

    if args.listeners:
        med = sum(1 for _, d in items if 'sdp_media' in d['stages'])
        print(f"two-axis media analysis: {len(items)} bridge(s) in window; "
              f"{med} carry sdp_media instrumentation")
        print("  recv = could our callee audio reach them (downlink — the 'listened' axis); "
              "sent = did they stream to us (uplink). Independent.")
        rt = collections.Counter(recv_status(d) for _, d in items)
        st = collections.Counter(sent_status(d, dumps) for _, d in items)
        print("\nrecv (downlink — 'may have listened' = reachable):")
        for v in ('reachable', 'unreachable', 'unknown'):
            if rt.get(v):
                print(f"  {v:12} {rt[v]:6}   {RECV_DESC[v]}")
        print("sent (uplink):")
        for v in ('engaged', 'silent'):
            if st.get(v):
                print(f"  {v:12} {st[v]:6}   {SENT_DESC[v]}")
        both = sum(1 for _, d in items
                   if recv_status(d) == 'reachable' and sent_status(d, dumps) == 'engaged')
        print(f"\nreachable AND engaged (strongest 'listened' candidates): {both} bridge(s)")

        # Per-actor roll-up. Keep any actor we can say something about: recv evaluable
        # OR uplink-engaged — so engaged-but-recv-unknown probes (pre-instrumentation)
        # still appear instead of being hidden. Drops only (recv=unknown, silent) noise.
        groups = collections.defaultdict(list)
        for _, d in items:
            if recv_status(d) != 'unknown' or sent_status(d, dumps) == 'engaged':
                groups[(d.get('ip'), d.get('num'))].append(d)
        rows = []
        for (ip, num), ds in groups.items():
            rc = collections.Counter(recv_status(x) for x in ds)
            sc = collections.Counter(sent_status(x, dumps) for x in ds)
            bth = sum(1 for x in ds
                      if recv_status(x) == 'reachable' and sent_status(x, dumps) == 'engaged')
            addr_c = collections.Counter(f"{x['sdp_ip']}:{x['sdp_port']}" for x in ds
                                         if x.get('sdp_ip') and recv_status(x) == 'reachable')
            raddr = addr_c.most_common(1)[0][0] if addr_c else '-'
            rows.append((rc.get('reachable', 0), bth, len(ds), ip, num, rc, sc, raddr))
        print(f"\nby source IP → destination, top {args.top} "
              f"(sorted by reachable, then both-directions):")
        for reach, bth, n, ip, num, rc, sc, raddr in \
                sorted(rows, key=lambda r: (-r[0], -r[1], -r[2]))[:args.top]:
            recvc = f"reach={rc.get('reachable',0)}/unr={rc.get('unreachable',0)}/?={rc.get('unknown',0)}"
            sentc = f"eng={sc.get('engaged',0)}/sil={sc.get('silent',0)}"
            print(f"  ip={ip or '?':16} num=+{num or '?':14} bridges={n:4} "
                  f"recv[{recvc:22}] sent[{sentc:14}] both={bth:<3} reach_addr={raddr}")
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
    rt = collections.Counter(recv_status(d) for _, d in items)
    st = collections.Counter(sent_status(d, dumps) for _, d in items)
    if rt.get('reachable') or rt.get('unreachable') or st.get('engaged'):
        both = sum(1 for _, d in items
                   if recv_status(d) == 'reachable' and sent_status(d, dumps) == 'engaged')
        print("\nmedia reachability (sdp_media instrumentation):")
        print(f"  recv (could hear our callee audio): reachable={rt.get('reachable',0)} "
              f"unreachable={rt.get('unreachable',0)} unknown={rt.get('unknown',0)}")
        print(f"  sent (streamed to us): engaged={st.get('engaged',0)} silent={st.get('silent',0)}")
        print(f"  reachable AND engaged: {both}   (run with --listeners for the per-actor roll-up)")
    dtmf_total = sum(len(d['dtmf']) for _, d in items)
    if dtmf_total:
        print(f"\nSIP-INFO/DTMF events: {dtmf_total} (run with --dtmf for detail)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
