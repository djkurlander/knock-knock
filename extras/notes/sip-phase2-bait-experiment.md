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
   into a new Asterisk `sticky-hold` context: `Answer` → brief ringback →
   realistic hold media (looping music/IVR) → **do not hang up** until the bot
   does or a cap. Gives CDR `billsec` + MixMonitor for free. Two flavors:
   - **Phase A — fake hold (free):** play our own audio, never dial out. No money moves.
   - **Phase B — real validation (paid):** actually `Dial(...@telnyx)` with a hard
     hold cap, used sparingly.
3. **Ban exemption** — add `MAX_KNOCKS_EXEMPT=<ip>` allowlist to `monitor.py`'s
   auto-ban path; `ip_ban.py --unban` the target first so it can return and
   escalate without being evicted at SIP:2000.
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
2. [ ] `MAX_KNOCKS_EXEMPT` allowlist — `monitor.py`.
3. [ ] Asterisk `sticky-hold` context + holdtime logging.

Implement Phase A (free) first.

## Success / negative criteria

- **Positive:** target escalates to longer/concurrent calls, or new IPs arrive to
  pump the blessed number ⇒ monetization behavior captured.
- **Negative (valuable):** durable, convincing, un-banned route triggers nothing
  ⇒ monetization is decoupled from the scanners ⇒ publishable finding.
