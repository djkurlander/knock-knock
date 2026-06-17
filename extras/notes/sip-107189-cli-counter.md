# SIP CLI-counter bot — `107.189.20.125` → `+33756758573`

**Date:** 2026-06-14
**Status:** Observed / open (interpretation revised 2026-06-16 — holds are
monetization-shaped, *not* distinguishable from verification; target carrier is
Transatel, an IRSF-favored mobile range)

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
destination is doubtful** (see caveats). **Interpretation revised (2026-06-16):** the
target's carrier is **Transatel** (an IRSF-favored mobile range) and the silent holds
are **monetization-shaped** — we cannot separate "verifying the route" from "earning
on it" from the honeypot, since the only discriminator (do minutes bill at
`+33756758573`?) is exactly what the decoy can't produce. The two behaviours ("does it
answer?" / "does it hold?") are still real; only the earlier *"not monetization"*
conclusion was an over-claim. See "Is `+33756758573` a real IRSF number?".

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

**Reading (revised 2026-06-16) — monetization-shaped, not distinguishable from
verification:** completing + holding with no media tells us the route *holds a real,
billable-shaped call*; whether that is the bot *testing* the route or *earning* on it
is the **same observable event** (ACK + ride the cap, silent). The only discriminator
— do minutes actually bill at `+33756758573`? — is exactly what the decoy can't
produce (no call lands there), so we can't call it "verification." A botnet may have
**no separate verify step at all**: a successful long billable hold *both* proves the
route *and* collects, so it can jump straight to holding (skip a dedicated verify
phase) — which is what 16× 20-min silent holds look like. The silence is consistent
with monetization: **IRSF/AIT bills on connect-time, not audio**. And `+337` being
"just a mobile" is **not** reassuring — carrier Transatel is an IRSF-leasing range
(see "Is `+33756758573` a real IRSF number?"). The earlier "route verification, not
monetization" was an over-claim.

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

## 20-minute holds + the abandon-timer (4 vs 30) capture evidence (2026-06-16)

`107.189.20.125` came back as the campaign's active holder and now **rides the full
`PBX_CALL_TIMEOUT=1200s` cap repeatedly**: **16 holds to `b2bua_timeout age=1200`
over ~2 days** (e.g. bridge `f01bf322d6`, caller `69540283999`, a ~19 MB / ~20-min
Asterisk WAV). Same shape as before, scaled up — it ACKs, holds to whatever cap we
set, and **never sends its own `BYE`**; our `b2bua_timeout` tears it down cleanly
(ACK+BYE). So we *still* have not found its natural ceiling — at 1200s it does not
voluntarily hang up — and a hold remains **silent**: **0 `.rtp` dumps ever for this
IP** (no inbound media on any call, including every hold). Pure signalling hold =
"can this route keep a real, billable-shaped call up?", not media passing.

**ACK is slow, which makes `PBX_ABANDON_SECONDS` the deciding knob.** f01bf322d6
ACKed **23.8s after the `200`**. A natural A/B confirmed the cost: the box ran
`PBX_ABANDON_SECONDS=4` for ~12–24h, then `30` since the night of 06-15. Under `4`
every one of these holders is torn down as `attacker_no_ack` ~4s after answer,
*before* its ~24s ACK — **zero captured**; under `30` all 16 came through. So `4` is
not "fine because most ACK fast" — for *this* deep-verifier the ACK lands ~24s out,
and `30` is required to see it (and sufficient: max observed ACK here ≈24s < 30).
See [sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md) "Field
observations" for the abandon-timer rationale.

**Bait implication:** the heavy 20-min verification investment makes this IP an
obvious live-permit candidate, **but** it is exactly the CLI-correlating bot (see
Caveats) — a Telnyx completion lands with *our* verified number, not its counter, so
its operator could spot the MITM. Prime to keep observing — and (caveat #2, revised)
the CLI mismatch is **not** actually a tell, so it is baitable after all; the real
gate is cost/ethics if `+337` is an IRSF terminator (below).

## Is `+33756758573` a real IRSF number? (2026-06-16)

Evidence leans **yes — an IRSF revenue terminator**, not the personal beacon assumed
earlier:

- **Carrier = Transatel** (`phonenumbers`): an MVNE whose `+33 7 5x` mobile ranges are
  repeatedly used as **leased IRSF/AIT terminators** — real-looking French mobiles that
  evade premium-range blocklists. "It's just a mobile" is the wrong read.
- **Sustained, high-volume, multi-source:** `dial_intel` shows **6007 hits,
  2026-04-19 → still active**. `knocks_sip` fan-in: **10 distinct source IPs across 4
  budget-hosting ASNs** (RouterHosting LLC / PebbleHost / HostPapa / unknown) — one
  coordinated campaign pumping the number for ~2 months.
- **Behaviour fits:** silent 20-min holds = duration-accrual, and IRSF/AIT bills on
  connect-time, not media — exactly what we see (**0 `.rtp` ever** for this IP).
- *Caveat:* it's a **lone** number in our data (the only `+3375x` dialed), not a cycled
  range — suggestive, not conclusive from in-DB alone.

**Bonus finding (separate target set):** the heavily-dialed
`+33412141011/012/014/015…` cluster is a block of **consecutive geographic (`04 12…`)
numbers** — contiguous leased ranges are an even stronger structural IRSF signature
than the lone mobile. Likely a different campaign; worth its own look.

**How to confirm (cheapest / most-decisive first):**
1. **Telnyx termination rate** — ✅ **done (2026-06-16): no rate signal.** Longest match
   for `+33756758573` is prefix `337` = "France – Mobile – **Non Surcharged**" @
   **$0.0594/min** (no finer `33756…` breakout exists). It is **not** in any surcharged
   / Special Services / Special Mobility / Globalstar bucket — those run **$0.54–$2.61**
   — so there is **no rate-inflation IRSF flag**. The `+334121…` block likewise bills as
   ordinary "France – Fixed – Local" @ **$0.0052**. Caveat: a normal rate does **not**
   exonerate — clean, normal-rate, real-looking numbers are the modern AIT/IRSF playbook
   (off-deck revenue share doesn't surface in a retail rate deck). **Bait upshot:** a live
   completion is **cheap (~$0.06/min → 5 min ≈ $0.30), routable, and low-harm**
   (negligible revenue-share leak on a non-surcharged number), which makes this a *more*
   attractive live-bait target, not less.
2. **GSMA RAG / IPRN test-number & AIT feeds** — a direct hit is conclusive (gated).
3. **HLR lookup** — serving network / live status; leased numbers route oddly.
4. **OSINT** — the number + "Transatel 0756 fraud"; who-called / scam aggregators.
5. **Capped privacy-mode probe** *(last resort)* — answer-fast-then-silence ≈ a
   terminator; but a real call **pays the revenue share**, so prefer (1).

## Interpretation (candidate)

The counter is plausibly a per-call **correlation/sequence token**: if the operator
controls `+33756758573`, "incoming call with CLI = X" reconciles against "scan attempt
#X / route Y" (the **destination cross-check** in
[sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md), "Bot verification
model"). This correlation behaviour is the **one soft lean toward verification** — a
pure monetizer needn't increment a per-call token — but it's weak (could just be the
tool's `From` generator). The earlier inference that `+337` "being a mobile" makes it a
cheap beacon rather than a revenue target is **wrong**: carrier Transatel is an
IRSF-favored range. Net: treat the holds as monetization-shaped, and the counter as at
most a hint of an additional correlation layer on top.

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

2. **Not reproducing the CLI is *not* a meaningful tell (revised 2026-06-16).** A live
   Telnyx completion can't present the bot's spoofed counter — and with
   `CALLERID(pres)=prohib` (privacy mode) we present **Anonymous**, not a *wrong*
   number. But per caveat #1, CLI passthrough is **rare on real routes** — most PBXs
   rewrite or withhold — so a call arriving *without* the counter is the **normal**
   outcome for a genuine compromised PBX, not an anomaly a competent operator could
   flag without also flagging most real routes. (This was earlier listed as a MITM
   tell; that contradicted caveat #1 and is **withdrawn**.) Worst case the operator's
   correlation **degrades from per-call-token to time matching** ("a call landed at
   `+337` ~when I scanned") — coarser but sufficient for a low-volume bait. Privacy
   mode also avoids leaking our Telnyx DID. Residual: if `+337` *rejects* anonymous
   calls the bait fails for an unrelated reason — minor; anonymous inbound is common.

## Implications for the bait experiment

- The decoy fake-answer never lands a call at `+33756758573`, so it fails the
  destination cross-check (by time *or* token) — only a live completion can pass it.
- A live completion satisfies "did it land?" by **time**; the missing CLI counter is
  **not** a tell (caveat #2) — its absence matches normal no-passthrough routes.
- So this bot **is** baitable via the live path despite the counter: a privacy-mode
  Telnyx completion to `+337`, held long enough to register, makes the operator's logs
  consistent by time.
- **Cost/ethics gate:** if `+337` is an IRSF terminator (likely — see the IRSF
  section), a real completion *pays the revenue share*. Run the free Telnyx rate-deck
  check first, cap hard (`--max-seconds`, `--max-calls`), and treat any live call as
  funding-the-fraud spend to be minimized.

## Next steps

- **Run the Telnyx rate-deck check** on `+33756758573` and the `+334121…` block (IRSF
  section, step 1) — the cheap, decisive IRSF confirmation.
- Investigate the `+33412141011/012/014/015…` **consecutive-block** target set as its
  own (likely separate) IRSF campaign.
- Decode the counter: timestamp (unit/epoch) vs. free clock; pin down the ~8,400/sec.
- Scan other bots for the same CLI-counter pattern.
- Whois/ASN/geo + history for `107.189.20.125`. (Fan-in already known: 10 IPs / 4
  budget-hosting ASNs, one campaign, ~2 months.)
