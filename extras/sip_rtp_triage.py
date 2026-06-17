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

No third-party deps beyond numpy (reuses the decoders in sip_rtp_to_wav.py).
"""
import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sip_rtp_to_wav import read_dump, _ulaw_decode, _alaw_decode  # noqa: E402

DECODE = {0: _ulaw_decode, 8: _alaw_decode}
WIN = 160  # 20 ms at 8 kHz, for windowed silence fraction


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
    args = ap.parse_args(argv)

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
    main()
