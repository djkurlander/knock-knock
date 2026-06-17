# SIP media-presence probes — bots streaming RTP audio to verify the forward media path

**Date:** 2026-06-16
**Status:** Observed / ongoing (one strong example, one suggestive second)

## Summary

A class of SIP toll-fraud bots, after their INVITE is answered, **transmit real
RTP audio** (a tone) toward the honeypot — not to carry content, but to assert
that the **forward media path works** (bot → PBX → onward). This is a distinct
probe dimension from the other two we see:

| probe dimension | tests | signature |
|---|---|---|
| answer supervision | does it ring/answer? | INVITE → `200`, no ACK, **no media** |
| **media presence** | **does my audio traverse the route?** | **real RTP (tone) after answer** |
| hold | can I keep a real call up? | ACK + ride the cap, no media |

(See the three-class table in [sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md)
and [sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md).) On a *real*
open PBX the tone would carry to the bot's own beacon/IPRN number, letting the
destination confirm a genuine, non-FAS (False Answer Supervision) connection. The
honeypot is a dead-end — it answers locally and never forwards — so the tone never
lands; we just capture the technique on the attacker's inbound RTP leg
(`PBX_RTP_DUMP_DIR`, see [`docs/ASTERISK_B2BUA_DEPLOYMENT.md`](../../docs/ASTERISK_B2BUA_DEPLOYMENT.md)
→ "Capture Bot Audio").

It's **not** independent of placing a call — the media flows *during* a call,
after answer. What's independent is the *concern* being tested: media delivery,
separate from signaling and from call duration.

## Two observed examples

| campaign / source | target | caller (From) | style | tone | distinct frames | evidence |
|---|---|---|---|---|---|---|
| **ab00day** / `172.110.223.203` | `+442039960320` | `+972595231231` (spoofed) | **sustained looped frame** | 666.67 Hz + harmonic comb; RMS 14458, peak 32124; ~5–15 s | **1** (byte-identical) | **strong** — 115 dumps; 10 controlled recordings in the original note |
| (unnamed) / `77.42.86.8` | `+97233751353` (`+972`) | `101` | **single ~0.58 s burst** | ~166 Hz fundamental + harmonics at 334/497/664 Hz; RMS 3294, peak 22908 | **87** (natural envelope, not symbols) | **weak** — 1 capture, 1.72 s |

Two styles, same purpose: ab00day loops one hardcoded frame continuously and
`BYE`s ~20 s in; `77.42.86.8` emits one short tone burst surrounded by silence
(envelope: off ~0.36 s · **on ~0.58 s** · off ~0.78 s). Different campaigns, no
infrastructure overlap.

## No per-call data encoded in the audio — but asymmetric evidence

- **ab00day: proven.** Across 10 controlled recordings the bot transmits **one
  distinct 20 ms G.711 frame**, byte-identical every call — identical audio cannot
  carry per-call data. It is a fixed probe tone. (Full analysis:
  [sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md).)
- **`77.42.86.8`: not yet established.** We have a **single** 1.72 s burst. It's a
  single tone (one fundamental, no DTMF, no modulation, no symbol structure), so
  *this* call encodes nothing — the 87 "distinct" frames are just the burst's
  attack/decay envelope, not 87 symbols. But one capture **cannot** rule out
  *cross-call* encoding (the technique the `107.189` bot uses in the CLI rather
  than audio — see [sip-107189-cli-counter.md](sip-107189-cli-counter.md)). That
  needs more captures from this IP, then the cross-call discriminator below.

## Detection: `extras/sip_rtp_triage.py`

A quick silent-vs-audio triage over `.rtp` dumps, no WAV conversion or listening.
For each dump it decodes G.711 and reports:

- **RMS / peak** — energy. ~0 = silence (keepalive / comfort noise / encoded
  silence); a tone sits in the thousands.
- **`%sil`** — share of 20 ms windows below the silence threshold (the on/off
  envelope).
- **distinct frames** — the ab00day discriminator: **1** distinct payload = a
  fixed looped probe tone (no data); **many** = varying audio (real audio, a
  natural burst, or possible encoded data — inspect further).

Labels: `silent`, `TONE(1-frame)`, `AUDIO` (energetic + varying), `NO-G711`.

```bash
python extras/sip_rtp_triage.py data/rtp_dumps/                    # ranked, loudest first
python extras/sip_rtp_triage.py data/rtp_dumps/ --only-interesting # hide silent/tone
python extras/sip_rtp_triage.py one.rtp                            # single file
```

Run over the 117 dumps on hand, it sorted them in one pass: **115 `TONE(1-frame)`**
(all ab00day, RMS 14458 / 1 distinct each — independently reproducing the original
finding), **1 `silent`** (`149.202.60.153`, 2-packet near-keepalive), and **1
`AUDIO`** — the `77.42.86.8` burst above. Convert a flagged file with
`extras/sip_rtp_to_wav.py` to listen / analyze further.

## Open / next

- **More `77.42.86.8` captures** to (a) confirm it's a repeatable technique for
  this campaign and (b) apply the cross-call distinct-payload test — does the tone
  (pitch / duration / timing) vary call-to-call?
- **Scan the broader corpus** (accumulating `.rtp` dumps; Asterisk-side `rx` WAVs)
  and **other honeypots' SIP captures** for more media-presence probers and other
  tone fingerprints (666.67 Hz vs. the ~166 Hz burst).
- Cross-reference media-presence probers against the campaign breakdowns in the
  phase-2 and embassy-beacon notes — is media-presence probing correlated with the
  "deep verifier" role (the one IP per campaign that does the expensive checks)?
