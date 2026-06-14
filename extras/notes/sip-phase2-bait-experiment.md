# SIP Phase-2 (Monetization) Bait Experiment — Plan

**Date:** 2026-06-13
**Status:** Planned (not yet implemented)

## Background

Honeypot SIP traffic is overwhelmingly **route discovery**: bots brute-force
dial-out prefixes (hundreds of variants per IP) against a dialed IPRN number,
get a `200 OK`, and hang up fast. We have **not** observed **phase 2**
(monetization — long, concurrent, billable calls on a validated route). See
[smb/sip context in the index]; the open question from the ab00day analysis
([sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md)) and the campaign
breakdown is whether these are route-test or revenue numbers, and whether
monetization ever returns to a route the bot believes works.

Two structural reasons we never see phase 2 today:
1. **We `200 OK` everything** — so a genuinely-completed call is indistinguishable
   from the hundreds of fake answers; the bot never gets a clean "this route
   works" signal (and "accepts every prefix" is itself a honeypot tell).
2. **One-shot / revert-to-fake** — completing a single call then reverting makes
   the route look flaky, not durably exploitable.
3. (Bonus) **Our own `MAX_KNOCKS` auto-ban** evicts the bot at SIP:2000 before it
   could return to escalate — though observed bots (172.110.223.203, 51.38.52.76,
   77.42.86.8) do recur after bans expire, so persistence isn't the blocker;
   behavior is (they return doing more discovery).

## Hypothesis

If a scanning bot is presented with **one clean, durable, reliably-completing
route**, it (or its campaign's cash-out infrastructure) will escalate to
monetization: prefix behavior collapses from brute-force to a single settled
dial string, and call holdtimes/concurrency grow.

**Negative result is also publishable:** if a durable, convincing, un-banned
route triggers nothing, that is strong evidence monetization is **decoupled from
the scanners** (separate infra, or they verify in ways a honeypot can't fool).

## Design

Present **one target bot** with **one blessed route**, everything else unchanged
(contains blast radius and cost).

### Target selection
One `(bot IP, number)` pair that is active, not currently banned, ideally already
showing a *settled-prefix* signature (primed to exploit). Candidates:
- `172.110.223.203` → `+442039960320` (ab00day; active, never banned).
- `199.119.200.67` → `+442039743932` (1 prefix, 1,534 calls — already post-discovery).

### Blessed route = E.164-only (chosen)
For the target bot + blessed number, **accept only the bare E.164** as a valid,
completing call: strip an optional leading `+`, and complete iff the dialed
digits exactly equal the target's E.164 digits. **`404` everything else** — all
prefix variants (`00…`, `011…`, `9…`, exotic), and all other numbers.

- **Why:** sharpest possible signal. Exactly one dial string completes, so the
  brute-force can only converge on one answer; the discovery→exploit transition
  is unmistakable in the data. Bots already try the bare number in their sweep.
- **Trade-off:** a real open PBX usually also accepts `00/011/9`, so "only bare
  E.164 works" is slightly atypical and a sharp bot could read it as odd.
- **Fallback:** if the target doesn't engage, widen to a small standard
  dial-out prefix set (`00`, `011`, `9`, bare) before abandoning.

## Four mechanisms

1. **Believable dialplan** *(implemented 2026-06-13)* — `sip_honeypot.py`
   `SIP_OK_DIALPLAN` decides which dialed forms the fake PBX answers (200) vs
   rejects (404), applied **globally** (a real PBX doesn't vary its dialplan by
   caller). Default `+,bare,00,011,9` answers the standard dial-out forms and
   404s the resolver's brute-strip/garbage forms that the old "answer everything"
   default fake-accepted — removing the "accepts every prefix" honeypot tell.
   A dial is accepted iff `canon(dial) == prefix + computed-E.164` (cache
   included); unresolvable numbers always 404. Knocks are still recorded before
   the gate. Replaces the deleted `SIP_INVITE_MODE` (`reject` → `none`; `ring`
   path removed). **The per-target bait lives one layer down**, not here: the
   existing `sip_live_permit` + `PBX_DIAL_POLICY` machinery (keyed on
   `client_ip`+number) is what actually completes a real, media-bearing call to a
   chosen bot — and bridging, not a media-less fake 200, is the signal a bot uses
   to conclude a route works. So no per-IP dialplan gating was needed.
2. **Sticky / durable completion** — route blessed-route calls through the B2BUA
   into a new Asterisk `sticky-hold` context: **answer fast** (≤1s ringback — bots
   CANCEL at ~3s, see Field observations) → keep RTP flowing with **silence**
   (`silence90.ulaw/.alaw`, matching real IPRN targets — *not* music/IVR) → **do
   not hang up** until the bot does or a ~90s cap. Gives CDR `billsec` + MixMonitor
   (recording length = holdtime) for free. Two flavors:
   - **Phase A — fake hold (free):** play our own audio, never dial out. No money moves.
   - **Phase B — real validation (paid):** actually `Dial(...@telnyx)` with a hard
     hold cap, used sparingly.
3. **Ban management** *(implemented 2026-06-13)* — no persistent exemption knob;
   not worth it at observed volumes (an active IP trips `SIP:2000` only every
   couple of days). Instead `ip_ban.py --unban <ip>` now zeroes
   `hits_since_cleared` as well as lifting the ban, so a single command gives the
   target a clean slate — usable both to recover after a ban and pre-emptively to
   keep it from tripping the limit. Run it occasionally while watching the
   experiment.
4. **Holdtime instrumentation** — capture how long each blessed-route call stays
   up (Asterisk CDR `billsec` + `tx`/`rx` recording durations; add INVITE→BYE
   timing on the raw-SIP path). This is the phase-2 detector.

## Phased plan (cheap first, money as fallback)

- **Phase A (free):** selective + **fake** sticky hold + ban-exempt + holdtime
  logging. Run for days. Escalation (settled prefix, longer/concurrent calls)
  ⇒ phase 2 baited at zero cost.
- **Phase B (paid, only if A yields nothing):** swap the blessed route to **real**
  Telnyx completion for a handful of *validation* calls (the bot may verify real
  billing at its destination before trusting a route), then revert to fake sticky
  for volume. Caps: per-call hold ≤ 60–90 s, total-minutes + total-$ budget,
  auto-disable after N real completions or $X spent.

## Metrics to log (and publish)

- Prefix-diversity over time for the target (brute-force → settled = the transition).
- Holdtime distribution of blessed-route calls (the monetization tail).
- Concurrency (simultaneous calls to the blessed number).
- New source IPs appearing on the blessed number after validation (cash-out infra).
- Latency from validation to first long call; whether it expands to other numbers.

## Safeguards (do not fund the fraudsters)

- Phase A moves **no money** (fake far-end; real number never dialed).
- Phase B: capped spend + minutes, valid Telnyx CLI (no spoofing), one target
  only, instant kill-switch (re-ban + disable blessed route).
- Research/harm-reduction goal: log everything in a form suitable for a
  disclosure / writeup to GSMA, carriers, or a public post.

## Build pieces (status)

1. [x] Believable global dialplan (`SIP_OK_DIALPLAN`, default `+,bare,00,011,9`)
   replacing `SIP_INVITE_MODE` — `sip_honeypot.py`. Per-target completion stays in
   the existing `sip_live_permit`/`PBX_DIAL_POLICY` layer (no per-IP dialplan).
2. [x] Ban management — `ip_ban.py --unban` now also resets `hits_since_cleared`
   (clean slate); no persistent exemption knob needed at observed volumes.
3. [ ] Asterisk `sticky-hold` context + holdtime logging.

Implement Phase A (free) first.

## Success / negative criteria

- **Positive:** target escalates to longer/concurrent calls, or new IPs arrive to
  pump the blessed number ⇒ monetization behavior captured.
- **Negative (valuable):** durable, convincing, un-banned route triggers nothing
  ⇒ monetization is decoupled from the scanners ⇒ publishable finding.

## Field observations

### 2026-06-14 — bots CANCEL at ~3s; answer-supervision timeout, not "instant hangup"

First live look on LA1 with a bridged bot (`15.204.184.126`, dialing `+421232229875`
via brute-forced prefixes). Every Asterisk recording was **44 bytes — an empty WAV
header, zero audio.** Looked like the bot hangs up the instant it's answered. The
SIP timing (pcap) showed the real cause:

```
+0.000  INVITE
+0.005  100 Trying
+0.088  183 Session Progress / 180 Ringing
+3.089  200 OK        <- we answer here (dialplan Progress→Ringing→Wait(3)→Answer)
+3.150  CANCEL        <- bot gives up ~60ms later
```

The bot **rings ~3s then CANCELs** — it has an answer-supervision timeout of ~3s.
Our dialplan answered at **exactly 3.09s** (`Wait(3)`), right at the edge, so the
`200 OK` and the bot's `CANCEL` crossed; the call never established and MixMonitor
captured nothing. **This is not proof the bot won't hold media** — we never gave it
a completed call.

**Action:** answer *inside* the bot's window — drop the pre-answer `Wait(3)` to
`Wait(1)` (or remove it) in `honeypot-inbound`, so the `200 OK` lands at ~1s with
~2s of margin. Then watch whether the empty 44-byte WAVs become real recordings
(bot sends `ACK`, media flows) or the bot still `CANCEL`s/`BYE`s instantly. Only the
latter would make it a pure supervision prober. **Implication for the silence-hold
work (#2/#3): answer-speed matters as much as not-hanging-up-first** — a sticky hold
is useless if we answer after the bot's timeout. Use plain silence (`silence90`,
matching the real targets), not music/IVR.

### 2026-06-14 (cont.) — it's cancel-*on-answer*, not a timeout; + a teardown bug

Reduced `Wait(3)→Wait(1)` and the bot **still CANCELs ~60ms after the `200`** — now
at age ~1.16s instead of ~3.15s. The cancel *tracks our answer*, so it is **not** a
fixed timeout: the bot waits for answer supervision, and the instant it sees the
`200` it CANCELs. It never `ACK`s, never passes media (0 `attacker_ack` across the
whole run; 26 `closed reason=attacker_cancel` vs 2 `b2bua_timeout`). A second bot,
`38.248.90.132`, does the same in **parallel** — 3 concurrent INVITEs to 3 numbers,
all canceled ~1.2s. **Verdict: these are pure answer-supervision discovery probers;
answering faster cannot win, there is no window.** (The 2 `b2bua_timeout` closes are
the interesting outliers — callers that did *not* cancel; worth chasing.)

**Teardown bug found + fixed (`sip_b2bua.py`).** The bot's `CANCEL` arrives *after*
the `200`, so it's invalid on an answered dialog — Asterisk ignored it and kept the
call up, playing the full `silence90` file to a departed attacker → minute-long
~1 MB **zombie** recordings (recording length was meaningless as holdtime; the truth
was `attacker_cancel age≈1.1s`). Fix: B2BUA now tracks `pbx_answered`/`pbx_acked`
and tears the PBX leg down with the correct verb — **`ACK`+`BYE` for an answered
dialog** (a bare `CANCEL` is ignored post-answer), `CANCEL` only pre-answer. Handles
the **CANCEL/200 glare**: a pre-answer cancel keeps the PBX leg alive so a 2xx racing
the cancel still gets `ACK`+`BYE` (`attacker_gone` branch) instead of zombying.

## Cost control — keep probers off the PBX/Telnyx (Phase-B billing safeguard)

These probers complete nothing, yet each one currently spins up an Asterisk channel
(and, on the live path, would risk a `Dial(@telnyx)`). Two layers to engage the
PBX/Telnyx **only for callers that prove they are serious**:

1. **Patience filter (dialplan-only, free, interim).** A longer pre-answer ring is a
   patience test: a throughput-optimised scanner hits its own timeout and CANCELs
   *before* we answer (a valid pre-answer cancel → Asterisk `487`, no answer, no
   media, no Telnyx); a caller that intends to pass traffic waits through it — and a
   long ring is *more* realistic, not less. We only know the probers' patience is
   `≥3s` (they sat through `Wait(3)`). **Measure it:** raise the ring (e.g.
   `Wait(15)`), then read `attacker_cancel age=X` traces that have **no preceding**
   `pbx_response code=200` — that `age` is the bot's timeout. Set the ring above the
   probers' patience but below a real caller's.

2. **Answer-first / bridge-on-ACK B2BUA (target architecture, the definitive gate).**
   Key on the actual completion signal (`ACK`), not a guessed patience threshold.
   *Chicken-and-egg:* `ACK` is the response to a `200`, which today comes from
   Asterisk — so "wait for ACK before starting the PBX call" requires the **B2BUA to
   answer the bot itself** (its own `100/18x/200` + local SDP), collect the `ACK`, and
   **only then** `INVITE` Asterisk and bridge. It promotes the B2BUA from transparent
   forwarder to an answer-first back-to-back UA (media stitching is already what it
   does; the new part is the sequencing). Result: Asterisk/Telnyx are engaged **only
   on `ACK`** ⇒ probers (which ~never ACK) cost $0 and never touch the PBX, while we
   still answer them locally (supervision signal + knock + local RTP dump preserved).
   Operator test calls force the bridge via the live permit regardless.

   **This is uniform across both paths, not live-only.** Live vs. decoy differ *only*
   in what happens *after* the `ACK` — `Dial(@telnyx)` (paid) vs. the silence-hold
   (free). The decision to engage Asterisk only on `ACK` is identical. Decoy gets the
   same wins (probers never touch Asterisk at all — bigger than the 4s abandon timer;
   one code path; decoy's purpose preserved since the bot still gets a local `200` and
   we still `rtp_dump` its tone). **Roll out live-first** purely for urgency (real $)
   and blast radius (low-volume, permit-gated) — then extend to decoy. The teardown +
   abandon-timer already shipped become the **post-ACK safety net** (a bot that ACKs,
   bridges, then vanishes without a `BYE` still needs the Asterisk leg torn down).

   - **Premise to validate first:** 0 `ACK`s observed so far. If no prober ever ACKs,
     the design simplifies to "answer all locally, touch PBX only on ACK/permit."
   - **Cost:** a real `sip_b2bua.py` refactor — do it after the patience measurement
     and once the 0-ACK premise holds.

   **Implementation sketch (`sip_b2bua.py`):**
   - **Bridge phases:** add a phase flag — `LOCAL` (we answered, no PBX yet) →
     `ENGAGED` (INVITEd Asterisk, relaying). `start()` no longer sends the PBX INVITE.
   - **Local UAS answer:** B2BUA sends `100` → optional `18x` ringback → `200` with its
     **own** SDP (`build_sdp(public_ip, attacker_rtp_port, ['0','8'])`) — the answer
     the bot reacts to. Allocate the attacker RTP socket + arm `rtp_dump` now so the
     probe tone is captured pre-ACK.
   - **Gate on ACK:** in `forward_in_dialog`, the bot's `ACK` (first one) calls a new
     `_engage_pbx()` — *that* is where today's `start()` INVITE-to-Asterisk + response
     relay lives. Pin G.711 both ways so no transcode when stitching the two legs.
   - **No-ACK paths stay local:** pre-engage `CANCEL`/abandon-timer/`b2bua_timeout`
     just tear down the local leg — Asterisk never involved, `$0`, no channel. Post-
     engage, the existing centralized `close()` teardown (ACK+BYE) applies unchanged.
   - **Live vs decoy after engage:** unchanged — Asterisk's dialplan still branches on
     `KNOCK_LIVE` (`Dial(@telnyx)` vs silence-hold); we just reach it only on `ACK`.

## Bot verification model — answer supervision vs. destination cross-check

The single most important strategic constraint, and why the `ACK` line is about
*credibility*, not just billing:

- **Our teardown is invisible to the bot.** The `ACK`/`BYE` we send is on the
  B2BUA↔Asterisk (far) leg. The bot only sees its *own* near-leg dialog — it INVITEd,
  got a `200`, CANCELed/abandoned. So tearing the far leg down early is **never** a
  signaling tell; from the bot's view it's a clean call it aborted itself.

- **Two levels of verification a bot/operator can use:**
  1. **Answer supervision** (the `200`) — *we* generate and fully control it. Fools the
     cancel/abandon probers; they log "answers" and never establish a session.
  2. **Destination cross-check** — "my scanner says route X answered → did a call
     actually *land/bill* on my premium number?" We do **not** control this. On the
     **decoy path no call ever reaches the real number**, so this check fails
     **regardless of teardown timing.** Only a genuine completion to the *dialed*
     number (live/Telnyx, held long enough for a CDR) makes the logs consistent.

- **What each teardown case implies about the bot's expectation:**
  - **CANCEL / abandon (no ACK):** answer supervision only, no session established ⇒
    expects no landed call, has nothing to cross-check ⇒ tear down freely (invisibly).
  - **BYE after ACK:** a fully established session ⇒ expects a real connected call and
    *may verify the landing* ⇒ must be a genuine completion, **not** canceled early.

- **Therefore the `ACK` is the credibility dividing line** (same one as billing/cost):
  no-ACK callers can't verify and can't see our teardown ⇒ free to tear down; an ACKing
  caller is exactly the one whose operator may cross-check the destination ⇒ route it to
  a **real, un-canceled completion to the actual number, held to register a CDR.** The
  abandon timer is safe by construction — it only fires when there's no ACK, i.e. no
  session and nothing to verify. So answer-first/ACK-gate is *credibility* protection:
  the precise callers who could catch us faking are the ones we complete for real.
