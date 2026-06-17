#!/usr/bin/env python3
"""Convert a honeypot B2BUA `.rtp` dump (KKRTP1) into a gap-accurate 8 kHz WAV.

The SIP honeypot B2BUA writes one `.rtp` file per bridged call when
`PBX_RTP_DUMP_DIR` is set (see honeypots/sip_b2bua.py). Each file holds the
attacker's inbound RTP — the pristine source-side copy of the audio the bot
streams after answer. This tool decodes G.711 (PCMU/PCMA) and reconstructs the
timeline from RTP timestamps, inserting silence for lost/missing packets so the
on/off beacon timing is preserved.

Usage:
    python extras/sip_rtp_to_wav.py capture.rtp [-o out.wav]
    python extras/sip_rtp_to_wav.py capture.rtp --info   # just print stats

No third-party deps beyond numpy.
"""
import argparse
import os
import struct
import sys
import wave

import numpy as np

MAGIC = b'KKRTP1\n'
REC = struct.Struct('>dHIBH')  # arrival_rel, seq, rtp_ts, payload_type, payload_len
CLOCK = 8000  # G.711 sample rate


def _ulaw_decode(b):
    u = 255 - np.frombuffer(b, dtype=np.uint8).astype(np.int32)
    sign = u & 0x80
    exp = (u >> 4) & 0x07
    mant = u & 0x0F
    mag = ((mant << 3) + 0x84) << exp
    mag -= 0x84
    out = np.where(sign != 0, -mag, mag)
    return out.astype(np.int16)


def _alaw_decode(b):
    a = np.frombuffer(b, dtype=np.uint8).astype(np.int32) ^ 0x55
    sign = a & 0x80
    exp = (a >> 4) & 0x07
    mant = a & 0x0F
    mag = np.where(exp == 0, (mant << 4) + 8, ((mant << 4) + 0x108) << (exp - 1))
    out = np.where(sign != 0, mag, -mag)  # A-law: sign bit set => positive
    return out.astype(np.int16)


def read_dump(path):
    with open(path, 'rb') as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError(f'{path}: not a KKRTP1 dump (bad magic)')
        pkts = []
        while True:
            head = f.read(REC.size)
            if len(head) < REC.size:
                break
            t_rel, seq, ts, pt, plen = REC.unpack(head)
            payload = f.read(plen)
            if len(payload) < plen:
                break
            pkts.append((t_rel, seq, ts, pt, payload))
    return pkts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rtp')
    ap.add_argument('-o', '--out', help='output WAV (default: alongside input)')
    ap.add_argument('--info', action='store_true', help='print stats only')
    args = ap.parse_args()

    try:
        pkts = read_dump(args.rtp)
    except ValueError as e:
        sys.exit(str(e))
    if not pkts:
        sys.exit(f'{args.rtp}: no packets')

    pts = {p[3] for p in pkts}
    seqs = [p[1] for p in pkts]
    # 16-bit sequence wrap-aware loss estimate
    span = (seqs[-1] - seqs[0]) & 0xFFFF
    lost = span + 1 - len(pkts)
    print(f'packets={len(pkts)} payload_types={sorted(pts)} '
          f'seq_span={span + 1} est_lost={lost} duration~{pkts[-1][0]:.2f}s')
    if args.info:
        return

    if pts - {0, 8}:
        print(f'warning: non-G.711 payload types present {sorted(pts - {0, 8})}; '
              f'those packets are skipped', file=sys.stderr)

    decode = {0: _ulaw_decode, 8: _alaw_decode}
    base_ts = pkts[0][2]
    chunks = []  # (sample_offset, samples)
    for _t, _seq, ts, pt, payload in pkts:
        if pt not in decode:
            continue
        off = (ts - base_ts) & 0xFFFFFFFF
        if off > CLOCK * 3600:  # >1h => timestamp wrap/garbage, anchor to end
            off = chunks[-1][0] + len(chunks[-1][1]) if chunks else 0
        chunks.append((off, decode[pt](payload)))

    total = max(off + len(s) for off, s in chunks)
    audio = np.zeros(total, dtype=np.int16)  # silence fills the gaps
    for off, s in chunks:
        audio[off:off + len(s)] = s

    out = args.out or os.path.splitext(args.rtp)[0] + '.wav'
    with wave.open(out, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(CLOCK)
        w.writeframes(audio.tobytes())
    print(f'wrote {out}  ({total / CLOCK:.2f}s, {total} samples)')


if __name__ == '__main__':
    main()
