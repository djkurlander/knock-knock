# SIP CLI-counter bot — `107.189.20.125` → `+33756758573`

**Date:** 2026-06-14
**Status:** Observed / open (interpretation refined — likely route verification, not monetization)

## Summary

`107.189.20.125` repeatedly dials a **single fixed French mobile** (`+33756758573`,
`+337…`) and stamps each call's caller ID (SIP `From` user) with a **monotonically
increasing, time-correlated counter**. The CLI values are synthetic (not real
numbers), so they're a *data field*, not a real caller ID. **Mostly** it's an
answer-supervision prober (INVITE → `200` → silent abandon, no ACK/media), **but
periodically it actually completes the call (ACK) and holds the line silently** —
the first observed completion in this whole investigation (see "Completion / hold").
The counter is a candidate "correlate-calls-to-logs" token — same idea as the
audio-beacon hypothesis ([sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md)),
but in the **caller ID rather than the audio**. **Whether it ever reaches a
destination is doubtful** (see caveats). Working interpretation: `+33756758573` is
the operator's own **verification beacon**, and both behaviours are **route testing
at two depths** ("does it answer?" / "does it hold a real call?"), not monetization.

## Observation (data)

- **Target:** `+33756758573` only (France, `+337` mobile). One distinct target.
- **Volume:** ~104 calls/hour, every ~30–60s, occasionally parallel pairs.
- **CLI (`sip_from_user`):** synthetic 11-digit values, strictly increasing with time:

  | time (UTC) | CLI |
  |---|---|
  | 05:12:04 | 18500848037 |
  | 06:07:38 | 18528901325 |

  → **+28,053,288 over ~55.5 min ≈ ~8,400/sec**, strictly monotonic. Same-second
  parallel calls differ by only 1–9 (≈ sub-ms apart at that rate), so it's a fast
  **time-derived clock**, not a per-call increment. ~8,400/sec is suggestively close
  to the **8 kHz telephony sample clock** but not exact at second resolution —
  decoding the exact unit/epoch is open.

- **Behaviour (majority):** silent-abandon — `200` received, never `ACK`ed, no RTP;
  bridge closes via `attacker_no_ack` (abandon timer). But ~1 in 5 it completes —
  see below.
- Recurring active prober (was LA1's every-~2-min regular earlier; not banned).

## Completion / hold — first observed completion (2026-06-14, `Wait(15)`)

With a realistic 15s ring, `107.189.20.125` **ACKed and held 3 of 16 calls** — the
first bot in the whole investigation to complete the call setup and stay on the line:

- `ACK` arrives **~0.5–1.9s after the `200`** (the bot reacts to the answer, fast).
- It then **holds silently until our 45s `b2bua_timeout` cap** — *it never sent a
  `BYE`; we cut it off*, so it would have held longer.
- **No media** — no RTP dump for any of the 3 holds (vs. the 80KB+ ab00day dumps that
  prove the capture works). It holds the *signalling* open, sends no audio.
- The 3 completions were **spread ~40–50 min apart** amid routine abandons —
  periodic "deep" calls vs. the cheap answer-supervision majority.

**Reading (silent hold = duration, not audio):** completing + holding with no media
is consistent with testing whether the route *holds a real, billable-shaped call*,
not with passing content. Combined with `+337` being a plain mobile and the CLI
counter pointing at a number they likely own, the better model is **route
verification at two depths** — "does it answer?" (abandon) and "does it hold a
completed call?" (ACK+hold) — against their **own beacon**, *not* monetization of
this number. Real monetization (premium IPRN numbers) would be different numbers,
later, only on routes that pass verification — which our decoy can't (the call never
reaches `+33756758573`, so their destination cross-check sees nothing).

**Measurement caveat:** at `PBX_ABANDON_SECONDS=4` we tear down any call whose `ACK`
hasn't arrived within 4s of answer. The 3 we caught ACKed at 0.5–1.9s, but some of
the "abandons" could be slower-ACK completions we cut early. Follow-up (in progress):
`PBX_ABANDON_SECONDS=30` + `PBX_CALL_TIMEOUT=300` + a 310s looped-silence dialplan, to
(a) stop cutting completions and (b) see the *true* holdtime — `BYE` at a consistent
duration ⇒ verification; rides to the 300s cap ⇒ duration-accrual.

## Campaign context (2026-06-14 evening) — it's not one bot

`107.189.20.125` is one IP in a larger **FR campaign**: ≥8 IPs share the single target
`+33756758573` (`107.189.20.125/.26.20`, `153.75.83.238/.90.242/.90.249`,
`144.172.94.33`, `45.61.148.193`, `172.86.114.75`, `104.223.22.102`), separate from the
SK campaign (`15.204.184.126` → `+421232229875`, no IP overlap). The **complete-and-hold
role rotates**: with the 300s cap, the deep-hold behaviour appeared on
`153.75.90.249` (caller `"test"`), which held **7/7 completions to the cap, never
`BYE`ing**, while `107.189.20.125` went quiet. So within a campaign **one IP does the
expensive completion at a time, the rest probe-and-abandon** — and the holder rides the
cap rather than holding a fixed duration. Full holder analysis +
the 1200s ceiling experiment:
[sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md) (2026-06-14 evening).

## Interpretation (candidate)

A per-call **correlation/sequence token**. If the operator controls
`+33756758573`, they could reconcile "incoming call with CLI = X" against "scan
attempt #X / route Y" — a live instance of the **destination cross-check** in
[sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md) ("Bot verification
model"). `+337` being a mobile (not a premium/IPRN number) fits an
**operator-controlled verification beacon** (cheap to receive on) rather than a
monetization target — i.e. discovery-phase route testing.

## Caveats (the crux — do not over-claim)

1. **Destination visibility depends on CLI passthrough, which is NOT general.**
   Most PBXs/SBCs rewrite the outbound CLI to an authorized DID; carriers validate
   it (STIR/SHAKEN etc.). An arbitrary `From` is commonly overwritten or rejected —
   so a downstream destination usually sees the *trunk's* CLI, not the counter. The
   CLI is the field *most* likely rewritten; reliable correlation would tag the
   *dialed number* instead. So the counter is plausibly any of:
   - **opportunistic** — works only on passthrough-permissive PBXs, and that call
     doubles as a **CLI-passthrough probe** ("did my number arrive intact?");
   - **bot-side bookkeeping** — the bot logs each numbered attempt's outcome itself;
     the destination never needs to see it;
   - **incidental** — just the tool's `From`-generation scheme.
   We can't disambiguate from the honeypot alone (we observe the raw `From` only
   because *we* don't rewrite it).

2. **We cannot reproduce the CLI in a live (Telnyx) experiment.** Telnyx (any
   compliant carrier) won't present a spoofed CLI — outbound uses a verified/owned
   number. A real completion to `+33756758573` lands with **our** Telnyx CLI, not the
   bot's counter. If the operator correlates by CLI, that call arrives matching **no
   token** → a tell that could expose the MITM. The live bait only works if their
   correlation is **CLI-agnostic** (time-based, or unique-destination tagging).

## Implications for the bait experiment

- The decoy fake-answer is **detectable** to a CLI-correlating operator: no call
  lands on `+33756758573`, so no token ever arrives.
- A live completion satisfies "did it land?" by **time**, but **not by CLI** (Telnyx
  restriction) — a CLI-correlating operator could still spot the mismatch.
- Credibly baiting this bot would need either (a) the operator correlating by
  time/destination rather than CLI, or (b) presenting the bot's CLI downstream —
  not possible via Telnyx, and only possible via a CLI-passthrough-permitting route,
  which *is* the fraud capability we won't provide.

## Next steps

- Confirm monotonicity/rate over a longer window; does the counter reset, and is it
  shared across any other targets/IPs (campaign fingerprint)?
- Decode the counter: timestamp (unit/epoch) vs. free clock; pin down the ~8,400/sec.
- Scan other bots for the same CLI-counter pattern.
- Whois/ASN/geo + history for `107.189.20.125`.
