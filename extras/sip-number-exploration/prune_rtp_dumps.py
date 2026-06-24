#!/usr/bin/env python3
"""Prune redundant RTP dumps — collapse identical steady tones, keep all real content.

The honeypot only writes a dump when a bot actually streams RTP, so `data/rtp_dumps/`
is already filtered to media-senders. But a few beacon IPs emit the same steady tone
hundreds of times, so most files are byte-equivalent copies of a handful of tones.

Dedup key: the **set of distinct frames** in a file (`hash(sorted(set(frames)))`).
Two files with the same distinct-frame set are built from identical audio building
blocks, so dropping copies is lossless — and this is phase/length/order-blind, so the
frame-misaligned variants of one tone all collapse together (a steady 444 Hz tone
captured at different offsets shares one frame-set).

Order-blindness is safe ONLY for stationary signals (a steady tone carries no info in
frame order). A *sequence* — DTMF digits, speech, a melody — encodes meaning in order,
so set-hashing must never see one. Guards, in order:
  - ALWAYS keep `*-pbx.rtp` — live-permit callee-leg / voicemail recordings.
  - ALWAYS keep files with decoded RFC2833 DTMF (telephone-event).
  - ALWAYS keep files newer than the review cutoff (not yet analyzed by /sip-daily-review).
  - Dedup ONLY stationary files — same distinct-frame set in every time-window. A DTMF
    sequence / speech / melody changes its palette over time → non-stationary → kept,
    so its ordering is never discarded. (Real voice is also huge-palette, doubly safe.)
  - Among the stationary tones, keep N oldest exemplars per (frame-set, source-IP) — the
    per-IP split preserves cross-IP shared-tooling evidence.

Review-safety: /sip-daily-review reads the dumps (media-sent cross-ref + window find +
whole-corpus fingerprint), so pruning lags the review — by default only files older than
the diary's last-entry write time (its mtime) are eligible.

Dry-run by default; pass --apply to delete.

Usage:
  python extras/sip-number-exploration/prune_rtp_dumps.py            # dry-run
  python extras/sip-number-exploration/prune_rtp_dumps.py --apply
  python extras/sip-number-exploration/prune_rtp_dumps.py --keep 3 --before "2026-06-20 00:00:00"
"""
import argparse
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DUMP_DIR = ROOT / "data" / "rtp_dumps"
DIARY = ROOT / "extras" / "notes" / "sip_daily_observations.md"

sys.path.insert(0, str(ROOT / "extras"))
from sip_rtp_triage import decode_dtmf      # RFC2833 DTMF guard          # noqa: E402
from sip_rtp_to_wav import read_dump        # raw frame access            # noqa: E402

STATIONARITY_WINDOWS = 4  # split each file into this many time-windows


def _frames_and_dtmf(path):
    """(non-empty RTP payloads in arrival order, decoded RFC2833 DTMF string)."""
    pkts = read_dump(str(path))
    return [pl for *_rest, pt, pl in pkts if pl], decode_dtmf(pkts)


def _frameset_hash(frames):
    return hashlib.md5(b"".join(sorted(set(frames)))).hexdigest()[:12]


def _is_stationary(frames, k=STATIONARITY_WINDOWS):
    """True iff the distinct-frame set is identical in every time-window — a steady
    tone. A sequence (DTMF digits, speech, melody) changes palette over time → False,
    so the order-blind set hash never collapses two different sequences."""
    n = len(frames)
    if n < k:
        return False                       # too short to judge → keep (conservative)
    full = set(frames)
    return all(set(frames[i * n // k:(i + 1) * n // k]) == full for i in range(k))


def _src_ip(name):
    p = name.split("-")
    return p[3] if (len(p) > 4 and p[2] == "nolive") else (p[1] if len(p) > 1 else "?")


def default_cutoff_ts():
    """Diary file mtime = when the last review was committed; anything newer is unreviewed."""
    try:
        return DIARY.stat().st_mtime
    except OSError:
        return 0.0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=str(DUMP_DIR), help="dump dir (default: data/rtp_dumps)")
    ap.add_argument("--keep", type=int, default=2,
                    help="oldest exemplars to keep per (frame-set, source-IP) (default: 2)")
    ap.add_argument("--before", default=None,
                    help="only prune files modified before this 'YYYY-MM-DD HH:MM:SS' UTC "
                         "(default: diary last-entry mtime — i.e. already reviewed)")
    ap.add_argument("--apply", action="store_true", help="actually delete (default: dry-run)")
    args = ap.parse_args(argv)

    if args.before:
        cutoff = datetime.strptime(args.before, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc).timestamp()
        cutoff_src = f"--before {args.before} UTC"
    else:
        cutoff = default_cutoff_ts()
        cutoff_src = f"diary mtime ({datetime.fromtimestamp(cutoff, timezone.utc):%Y-%m-%d %H:%M:%S} UTC)"

    paths = sorted(Path(args.dir).glob("LA1-*.rtp"), key=lambda p: p.stat().st_mtime)
    if not paths:
        print(f"no dumps in {args.dir}", file=sys.stderr)
        return 0

    kept_pbx = kept_unreviewed = kept_content = 0
    groups = {}  # (frameset_hash, src_ip) -> [paths oldest-first]
    for p in paths:
        if p.name.endswith("-pbx.rtp"):
            kept_pbx += 1
            continue
        if p.stat().st_mtime >= cutoff:
            kept_unreviewed += 1
            continue
        try:
            frames, dtmf = _frames_and_dtmf(p)
        except Exception:
            kept_content += 1                # unreadable → keep
            continue
        # Only a steady, stationary, non-DTMF tone is ever a dedup candidate.
        if not frames or dtmf or not _is_stationary(frames):
            kept_content += 1
            continue
        groups.setdefault((_frameset_hash(frames), _src_ip(p.name)), []).append(p)

    to_delete, kept_exemplars = [], 0
    for _key, fps in groups.items():
        kept_exemplars += min(len(fps), args.keep)
        to_delete.extend(fps[args.keep:])    # fps already oldest-first

    del_bytes = sum(p.stat().st_size for p in to_delete)
    total_bytes = sum(p.stat().st_size for p in paths)

    print(f"dump dir: {args.dir}")
    print(f"review cutoff: {cutoff_src} — files newer than this are protected (unreviewed)")
    print(f"keep per (frame-set, IP): {args.keep}\n")
    print(f"  total files:                 {len(paths):5}  ({total_bytes/1e6:.1f} MB)")
    print(f"  protected -pbx (VM):         {kept_pbx:5}")
    print(f"  protected unreviewed:        {kept_unreviewed:5}")
    print(f"  protected content (non-stationary/DTMF): {kept_content:5}")
    print(f"  kept tone exemplars:         {kept_exemplars:5}  across {len(groups)} (frame-set, IP) group(s)")
    print(f"  -> deletable (surplus steady-tone copies): {len(to_delete):5}  ({del_bytes/1e6:.1f} MB)\n")

    for p in to_delete:
        print(("DELETE " if args.apply else "would delete ") + p.name)

    if args.apply:
        for p in to_delete:
            p.unlink()
        print(f"\ndeleted {len(to_delete)} files, freed {del_bytes/1e6:.1f} MB")
    else:
        print(f"\ndry-run: nothing deleted. Re-run with --apply to remove the {len(to_delete)} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
