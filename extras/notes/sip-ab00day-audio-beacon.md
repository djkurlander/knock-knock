# SIP Bot "Audio Beacon" Analysis — `ab00day` / 172.110.223.203

**Date:** 2026-06-12 → 2026-06-13
**Status:** Resolved — negative result.

## TL;DR

A SIP toll-fraud bot (campaign tag `ab00day`, source `172.110.223.203`) plays a
buzzy "modem/Morse-like" tone after its calls connect. We suspected it encoded
an identifier (honeypot IP, dial string, or a per-call counter) in the audio so
the destination could correlate which open PBX a call came through.

It does not. Across **10 controlled recordings** (same source IP, same target
number) the bot transmits **one byte-identical 20 ms G.711 tone frame on loop** —
exactly **1 distinct payload across all 10 calls**. Identical audio every call
**cannot carry per-call data.** It is a fixed **answer / media-presence probe
tone** (confirms a billable, non-FAS route connected). The per-call variation is
entirely at the **SIP layer** — the bot enumerates PBX dial-out prefixes — which
the honeypot already logs in `knocks_sip`.

## How the audio was captured

The honeypot B2BUA (`honeypots/sip_b2bua.py`) relays the attacker's RTP. With
`PBX_RTP_DUMP_DIR` set it writes the attacker-side inbound RTP to a per-bridge
`.rtp` file (pristine, source-side, before any Asterisk jitter buffer / transcode
/ PSTN hop). Convert with `extras/sip_rtp_to_wav.py`. See
`docs/ASTERISK_B2BUA_DEPLOYMENT.md` → "Capture Bot Audio (Raw RTP Dump)".

Reconstruction matters: **by RTP timestamp** = the bot's true generated audio;
**by arrival time** = what a real-time recorder (Asterisk MixMonitor) hears. The
"on/off Morse" pattern only appears in the arrival view — it is the constant
looped tone delivered in bursts, not encoded data.

## The SIP events that triggered these recordings

All from `172.110.223.203` (Philippines, ISP "Husam A. H. Hijazi"), spoofed
caller `+972595231231`, method INVITE, `sip_pbx_state=1` (bridged), no live
permit. Same target `+442039960320` every time — only the **dial-out prefix**
changes (prefix enumeration).

| knock id | timestamp (UTC) | dial string | prefix | bridge id | recording |
|---|---|---|---|---|---|
| 465447 | 2026-06-12 22:28:10 | `005442039960320` | 005 | ff5c592d41 | ff5c592d41…1781303290.rtp |
| 465501 | 2026-06-12 22:47:07 | `009442039960320` | 009 | 69b869eead | 69b869eead…1781304427.rtp |
| 465561 | 2026-06-12 23:08:03 | `008442039960320` | 008 | 4d46b44120 | 4d46b44120…1781305683.rtp |
| 465625 | 2026-06-12 23:30:47 | `007442039960320` | 007 | 63786c00d1 | 63786c00d1…1781307047.rtp |
| 465699 | 2026-06-12 23:54:35 | `001442039960320` | 001 | 5f1f6bd310 | 5f1f6bd310…1781308475.rtp |
| 465842 | 2026-06-13 00:44:04 | `0021442039960320` | 0021 | 995a515ee2 | 995a515ee2…1781311444.rtp |
| 465923 | 2026-06-13 01:12:23 | `0015442039960320` | 0015 | fff0142641 | fff0142641…1781313143.rtp |
| 466017 | 2026-06-13 01:42:22 | `9442039960320` | 9 | 2592815a2e | 2592815a2e…1781314942.rtp |
| 466101 | 2026-06-13 02:13:20 | `99442039960320` | 99 | f039e5d5a7 | f039e5d5a7…1781316800.rtp |
| 466182 | 2026-06-13 02:43:56 | `90442039960320` | 90 | ffeedb4a51 | ffeedb4a51…1781318636.rtp |

## Per-recording audio metrics

`true_s` = media duration from RTP timestamps; `arr_s` = wall-clock arrival span;
`gaps` = inter-packet arrival gaps > 40 ms; `uniq` = distinct 160-byte payloads.

| bridge id | bytes | pkts | true_s | arr_s | gaps>40ms | uniq payloads |
|---|---|---|---|---|---|---|
| ffeedb4a51 | 7,972 | 45 | 0.90 | 14.3 | 25 | 1 |
| 69b869eead | 26,026 | 147 | 2.94 | 14.4 | 35 | 1 |
| ff5c592d41 | 50,806 | 287 | 5.74 | 15.3 | 15 | 1 |
| fff0142641 | 61,426 | 347 | 6.94 | 15.5 | 45 | 1 |
| 995a515ee2 | 71,161 | 402 | 8.04 | 11.3 | 27 | 1 |
| 4d46b44120 | 76,117 | 430 | 8.60 | 15.6 | 38 | 1 |
| 5f1f6bd310 | 80,188 | 453 | 9.06 | 15.5 | 58 | 1 |
| 63786c00d1 | 81,250 | 459 | 9.18 | 15.6 | 40 | 1 |
| f039e5d5a7 | 86,737 | 490 | 9.80 | 14.3 | 57 | 1 |
| 2592815a2e | 107,269 | 606 | 12.12 | 18.8 | 44 | 1 |

**Distinct 160-byte payloads across all 10 recordings: 1.**

## Signal characterization

- Pitch: a perfectly machine-locked **666.67 Hz = 8000/12** (12-sample period),
  std 0.0 across every frame of every call. Harmonic comb at 1334/2000/2667 Hz.
- The repeated frame is **160 bytes (20 ms) of µ-law**, md5 `980b7e2c90fe`, an
  asymmetric/clipped waveform (PCM range −32124..+9852 — not a clean sine).
- 160 samples = 13.33 periods of 666.7 Hz (non-integer), so each loop boundary
  injects a **50 Hz buzz** → that is the harmonic-rich "modem" timbre.
- True (timestamp) audio amplitude is flat: 5 ms-window RMS mean 14452, std 403,
  **0% silent frames**. No amplitude or frequency modulation at sample resolution.

## Interpretation

The bot loops one hardcoded tone frame to assert live two-way media after
answer — standard IRSF route verification (is this a real, billable, non–False
Answer Supervision connection?). It does **not** identify the source PBX via the
media. Route attribution is done out-of-band: the call simply **arriving** at the
attacker-controlled `+442039960320` confirms the route, and the **dialed prefix**
that succeeded tells them how to reach an outside line from that PBX. The honeypot
records all of that at the SIP layer (`knocks_sip`).

## Call lifecycle (2026-06-15)

The *shape* of an ab00day call (from B2BUA traces, with a `Wait(15)` ring):

```
started → 100 → 183 → 180 → 200 (retransmitted ~4×, NO ACK)
attacker_bye age≈20s
closed reason='attacker_bye'
```

- **Never ACKs** — the `200` is retransmitted for want of an ACK, like the plain
  answer-supervision probers. It blasts RTP without completing the dialog.
- **Holds ~5s post-answer** (answer ~15s via the ring, BYE ~20s) — that ~5s is the
  tone window; the ~5–8s recordings (`77804`–`120684` bytes) are exactly it.
- **Ends with an explicit `BYE` at ~20s** — it doesn't silently vanish or ride a cap.

So ab00day is a **media-presence probe**, a third class distinct from the others seen:
| class | ACK? | media? | ends |
|---|---|---|---|
| answer-supervision prober | no | no | silent → cut at the abandon timer |
| **ab00day (tone)** | **no** | **yes (~5s tone)** | **explicit `BYE` ~20s** |
| "holder" (e.g. 153.75.90.249) | yes | no | rides to the cap, never BYEs |

The three test *different* things: answer supervision (does it ring?), media path
(does my tone go through?), and duration (can I keep the line up?). ab00day cares
about the media path, which is why it bothers to send the tone but not to hold.

## Reproduce / discriminator

The one-line test for any future bot — count distinct RTP payloads across calls:

```python
# >1 distinct payload  => audio varies => possible encoded data
# ==1 distinct payload => fixed looped frame => probe tone, no data
```

(see the `uniq payloads` column above; full procedure in this repo's git history
for commit `43b0d02`).

## Scope / caveats

Conclusive for the `172.110.223.203` / `ab00day` bot. A denser bot,
`51.38.52.76` (US, targeting `+12132610503`), was seen earlier only via
Asterisk MixMonitor WAVs (no pristine RTP) and showed the same 666.7 Hz tone, so
it is very likely the same mechanism — but it has not been confirmed at the RTP
payload level. If captured, run the discriminator above.
