#!/usr/bin/env python3
"""Silent-vs-audio triage for B2BUA `.rtp` dumps — no WAV conversion, no listening.

For each KKRTP1 dump (written by honeypots/sip_b2bua.py when PBX_RTP_DUMP_DIR is
set) this decodes G.711 and reports, per file:

  rms        overall RMS of the decoded PCM (int16 scale). ~0 = silence; a tone
             like the ab00day beacon sits in the thousands.
  peak       max abs sample.
  %sil       share of 20 ms windows below the silence RMS threshold.
  distinct   number of distinct payload frames. A single distinct frame is the
             fixed looped probe tone from extras/notes/sip-ab00day-audio-beacon.md
             (carries no per-call data); many distinct frames = varying audio.

label heuristic:
  silent         rms below --min-rms (keepalive / comfort noise / encoded silence)
  TONE(1-frame)  energetic but a single looped frame (probe tone, no data)
  AUDIO          energetic and varying (real audio / possible encoded data)
  NO-G711        no decodable PCMU/PCMA payloads (inspect payload_types by hand)

Usage:
    python extras/sip_rtp_triage.py data/rtp_dumps/             # scan a directory
    python extras/sip_rtp_triage.py data/rtp_dumps/*.rtp        # globbed files
    python extras/sip_rtp_triage.py capture.rtp                 # one file
    python extras/sip_rtp_triage.py data/rtp_dumps/ --min-rms 200 --only-interesting
    python extras/sip_rtp_triage.py data/rtp_dumps/ --fingerprint        # group by tone md5
    python extras/sip_rtp_triage.py data/rtp_dumps/ --fingerprint --match-md5 980b7e2c90

`--fingerprint` (alias `--beacon`) groups dumps by their modal-frame md5 + tone
frequency: the same md5 seen from multiple source IPs/ASNs means a shared toolkit
(e.g. the 666.7 Hz `980b7e2c90` beacon emitted by both ab00day and 51.38.52.76).

No third-party deps beyond numpy (reuses the decoders in sip_rtp_to_wav.py).
"""
import argparse
import collections
import hashlib
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sip_rtp_to_wav import read_dump, _ulaw_decode, _alaw_decode  # noqa: E402

DECODE = {0: _ulaw_decode, 8: _alaw_decode}
WIN = 160  # 20 ms at 8 kHz, for windowed silence fraction


def _src_from_name(path):
    """Pull (source_ip, dialed_number) from a dump filename, handling both the
    bridged form `LA1-<ip>-<fromuser>-<num>-<epoch>-<bridgeid>.rtp` and the older
    `LA1-<bridgeid>-nolive-<ip>-<num>-<epoch>.rtp` form."""
    p = os.path.basename(path).split('-')
    if len(p) > 4 and p[2] == 'nolive':
        return p[3], p[4]
    if len(p) > 3:
        return p[1], p[3]
    return '?', '?'


def _dom_freq(samp):
    """Dominant tone frequency (Hz) of a frame via autocorrelation, or None."""
    s = samp - samp.mean()
    if len(s) < 24 or s.std() < 1e-6:
        return None
    ac = np.correlate(s, s, 'full')[len(s) - 1:]
    if ac[0] == 0:
        return None
    ac = ac / ac[0]
    rng = range(8, min(60, len(ac) - 1))
    best = max(rng, key=lambda l: ac[l])
    return 8000.0 / best if ac[best] > 0.5 else None


def fingerprint(path):
    """Modal-frame md5 + dominant tone for a dump — a generator-agnostic signature.
    The same md5 from multiple source IPs/ASNs ⇒ shared tooling (e.g. the 666.7 Hz
    `980b7e2c90` beacon shared by ab00day and 51.38.52.76)."""
    pkts = read_dump(path)
    audio = [(pt, pl) for _t, _seq, _ts, pt, pl in pkts if pt in DECODE and pl]
    if not audio:
        return None
    modal = collections.Counter(pl for _pt, pl in audio).most_common(1)[0][0]
    pt = next(pt for pt, pl in audio if pl == modal)
    ip, num = _src_from_name(path)
    return {'path': path, 'md5': hashlib.md5(modal).hexdigest()[:10],
            'freq': _dom_freq(DECODE[pt](modal).astype(np.float64)),
            'ip': ip, 'num': num, 'distinct': len({pl for _pt, pl in audio})}


def analyze(path, silent_rms):
    pkts = read_dump(path)  # raises ValueError on bad magic
    if not pkts:
        return {'path': path, 'n': 0, 'label': 'EMPTY', 'rms': None,
                'peak': None, 'silent_frac': None, 'distinct': 0,
                'dur': 0.0, 'pts': []}
    pts = sorted({p[3] for p in pkts})
    distinct = len({p[4] for p in pkts})
    frames = [DECODE[pt](payload).astype(np.float64)
              for _t, _seq, _ts, pt, payload in pkts if pt in DECODE and payload]
    if frames:
        samp = np.concatenate(frames)
        rms = float(np.sqrt(np.mean(samp ** 2)))
        peak = int(np.max(np.abs(samp)))
        nwin = len(samp) // WIN
        if nwin:
            w = samp[:nwin * WIN].reshape(nwin, WIN)
            wr = np.sqrt(np.mean(w ** 2, axis=1))
            silent_frac = float(np.mean(wr < silent_rms))
        else:
            silent_frac = float(rms < silent_rms)
        label = 'silent' if rms < silent_rms else ('TONE(1-frame)' if distinct == 1 else 'AUDIO')
    else:
        rms = peak = silent_frac = None
        label = 'NO-G711'
    return {'path': path, 'n': len(pkts), 'label': label, 'rms': rms, 'peak': peak,
            'silent_frac': silent_frac, 'distinct': distinct,
            'dur': pkts[-1][0], 'pts': pts}


def collect_paths(args_paths):
    paths = []
    for p in args_paths:
        if os.path.isdir(p):
            paths.extend(sorted(os.path.join(p, f) for f in os.listdir(p) if f.endswith('.rtp')))
        else:
            paths.append(p)
    return paths


def _fingerprint_report(paths, match_md5):
    fps = []
    for path in paths:
        try:
            fp = fingerprint(path)
        except (ValueError, OSError) as e:
            print(f'  skip {path}: {e}', file=sys.stderr)
            continue
        if fp:
            fps.append(fp)
    if match_md5:
        sel = [f for f in fps if f['md5'].startswith(match_md5)]
        print(f"dumps with modal-frame md5 ~ {match_md5}: {len(sel)}")
        for f in sorted(sel, key=lambda f: (f['ip'], f['path'])):
            fr = f"{f['freq']:.1f}Hz" if f['freq'] else 'n/a'
            print(f"  {f['md5']}  {fr:>9}  ip={f['ip']:16} num=+{f['num']:14} "
                  f"{os.path.basename(f['path'])}")
        return 0
    groups = collections.defaultdict(lambda: {'n': 0, 'ips': set(), 'nums': set(), 'freq': None})
    for f in fps:
        g = groups[f['md5']]
        g['n'] += 1
        g['ips'].add(f['ip'])
        g['nums'].add(f['num'])
        g['freq'] = g['freq'] or f['freq']
    print(f"{len(fps)} dump(s); {len(groups)} distinct modal-frame fingerprint(s). "
          f"Shared md5 across IPs ⇒ same generator/toolkit.\n")
    print(f"{'md5':<11}{'freq':>9}{'files':>7}  {'src IPs':<36} sample dialed")
    for md5, g in sorted(groups.items(), key=lambda kv: -kv[1]['n']):
        fr = f"{g['freq']:.1f}Hz" if g['freq'] else 'n/a'
        ips = ', '.join(sorted(g['ips']))
        nums = ', '.join('+' + n for n in sorted(g['nums'])[:4])
        flag = '  <- multi-IP toolkit' if len(g['ips']) > 1 else ''
        print(f"{md5:<11}{fr:>9}{g['n']:>7}  {ips:<36} {nums}{flag}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('paths', nargs='+', help='.rtp files, globs, or a directory')
    ap.add_argument('--min-rms', type=float, default=50.0,
                    help='RMS (int16) below which a file is "silent" (default 50)')
    ap.add_argument('--only-interesting', action='store_true',
                    help='print only non-silent, decodable files')
    ap.add_argument('--sort', choices=('rms', 'name', 'dur'), default='rms',
                    help='sort order (default: rms, loudest first)')
    ap.add_argument('--fingerprint', '--beacon', action='store_true', dest='fingerprint',
                    help='group dumps by modal-frame md5 + tone freq (shared md5 across '
                         'IPs = same toolkit, e.g. the 666.7 Hz 980b7e2c90 beacon)')
    ap.add_argument('--match-md5', metavar='PREFIX',
                    help='with --fingerprint: list individual dumps whose modal-frame '
                         'md5 starts with PREFIX')
    args = ap.parse_args(argv)

    if args.fingerprint:
        return _fingerprint_report(collect_paths(args.paths), args.match_md5)

    rows = []
    for path in collect_paths(args.paths):
        try:
            rows.append(analyze(path, args.min_rms))
        except (ValueError, OSError) as e:
            print(f'  skip {path}: {e}', file=sys.stderr)

    interesting = {'AUDIO', 'TONE(1-frame)'}
    if args.only_interesting:
        rows = [r for r in rows if r['label'] in interesting]

    if args.sort == 'rms':
        rows.sort(key=lambda r: (r['rms'] is None, -(r['rms'] or 0)))
    elif args.sort == 'dur':
        rows.sort(key=lambda r: -r['dur'])
    else:
        rows.sort(key=lambda r: r['path'])

    print(f"{'label':<14}{'rms':>8}{'peak':>8}{'%sil':>7}{'dist':>6}{'pkts':>7}"
          f"{'dur':>8}  ptypes  file")
    n_interesting = 0
    for r in rows:
        if r['label'] in interesting:
            n_interesting += 1
        rms = f"{r['rms']:.0f}" if r['rms'] is not None else '-'
        peak = f"{r['peak']}" if r['peak'] is not None else '-'
        sil = f"{r['silent_frac'] * 100:.0f}%" if r['silent_frac'] is not None else '-'
        print(f"{r['label']:<14}{rms:>8}{peak:>8}{sil:>7}{r['distinct']:>6}{r['n']:>7}"
              f"{r['dur']:>7.1f}s  {','.join(map(str, r['pts'])) or '-':<7} "
              f"{os.path.basename(r['path'])}")
    print(f"\n{len(rows)} file(s); {n_interesting} interesting "
          f"(non-silent, decodable).")


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        # downstream (head/grep) closed the pipe — redirect stdout to devnull so
        # the interpreter's final flush doesn't re-raise, then exit quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
