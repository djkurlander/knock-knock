# SIP experiment & TODO backlog

Parking lot for SIP / B2BUA experiment ideas and deferred work, so they aren't lost.
Promote an item to its own `sip-<topic>.md` note (or implement it) when picked up;
strike it through / remove when done.

---

## Deferred: in-dialog responsiveness probe (mid-call re-INVITE / session refresh)

**Status:** Deferred 2026-06-20 (design agreed; not needed yet)

**Goal.** Distinguish a *sophisticated long-hold monetizer* (a real UA that handles the
dialog and could survive an enforcing route) from a *crude fire-and-forget dialer* (only
holds on permissive routes). Concretely: mid-call, poke the bot with an in-dialog request
and see whether it answers.

**Why two channels exist for "committed to the hold."** To keep a call alive against a
real carrier, a bot must cope with two *independent* teardown mechanisms:
1. **RTP-inactivity teardown** (unsignaled, unilateral) → defended by **keepalive RTP**:
   the bot proactively sends the occasional packet. Observable passively (stray RTP) or by
   enforcing an inactivity timeout and watching who defends.
2. **Session timers** (RFC 4028, negotiated) → defended by **responding to / originating
   a session refresh** (re-INVITE / UPDATE). A bot can offload *originating* the refresh to
   the far side, but on an enforcing route it must at least **respond** to the PBX's refresh
   or the call is torn down.

**Why deferred.** The keepalive-RTP channel (#1) already yields the "committed long-term"
signal we mainly care about — an occasional RTP packet shows commitment. The re-INVITE probe
(#2) is a *different channel* (signaling vs media) and confirms the bot is a real
dialog-handling UA, but for the "is it committed" question it's largely **duplicative**.
Revisit when we specifically want to separate "defends via media keepalive" from "handles
in-dialog signaling," or to grade UA sophistication / FAS-resistance.

**Preferred design (agreed): drive it from Asterisk, relay it in the B2BUA.**
Not a hand-rolled B2BUA-originated re-INVITE (too much transaction state / retransmit / CSeq
FSM in our Python). Instead:
- **Asterisk owns the state machine.** Enable native `res_pjsip` session timers on the
  honeypot endpoint (`timers`, `timers_sess_expires`, `timers_min_se`, Asterisk as
  refresher). Asterisk drives periodic re-INVITE/UPDATE with correct timing, retransmits
  (Timer A/B), CSeq, dialog state — battle-tested, and **more realistic / least
  fingerprintable** than a synthetic one-shot (no randomization hacks needed).
- **B2BUA does a thin relay.** Forward the in-dialog re-INVITE/UPDATE from the Asterisk leg
  to the bot, relay the bot's response back to Asterisk, relay Asterisk's ACK to the bot —
  reusing the existing per-leg dialog mapping. No timers/retries in the B2BUA. Hooks:
  `_handle_pbx_request` (Asterisk→bot direction) and `forward_in_dialog` (bot→Asterisk).
- **Observable signal:** the bot's response to the refresh — `200` (real UA, handles the
  dialog → sophisticated) / `4xx` e.g. `481` (real stack, discarded dialog state) / no
  answer (fire-and-forget). Trace it for the `b2bua_trace.py` classifier.

**Coupling caveat (ship together).** Asterisk session timers + the B2BUA relay are a
package: enable Asterisk timers *without* the relay and Asterisk's unanswered refresh tears
down the very holds we want to watch. (Confirm session timers are currently OFF on the
endpoint — they should be, since holds reach the 1200s cap fine today.)

**Architecture note.** The B2BUA is two independent back-to-back dialogs (`bot↔B2BUA`,
`B2BUA↔Asterisk`); a re-INVITE on one leg never confuses the other as long as we don't
cross-relay incorrectly. Asterisk can't reach the bot directly, so the B2BUA is
unavoidably in the path — the design just keeps its role to mechanical relay.

---

## Deferred: per-number / per-block answer-characteristic replay ("dial profiling")

**Status:** Deferred 2026-06-22 (design agreed; schema fields TBD)

**Goal.** Make the honeypot's *answer* for a target number indistinguishable from the
*real* number's, by **measuring the real call profile once and replaying it** thereafter.
Defeats the hardest honeypot/FAS check — *call the number directly, call it through the
suspected route, and compare*: generic realism fails the compare; a per-number replay
(same ring time, same VM greeting, same disposition) matches. Cheap because few new target
numbers appear per day (~≤5), and cheaper with block-dedup. **Supersedes** the earlier
"answer-realism hardening" idea — replay beats synthesized realism.

**Reference call (corrected cost model).**
- On first sight of a new, unprofiled, *resolvable-E.164* number: if it's a member of a
  **known cohesive block**, reuse that block's profile (no call); else place **one**
  live-permit reference call (existing live dial-out + raw callee-RTP capture) from a
  **burner DID**.
- Billing starts at **answer (`200`)**; Telnyx bills a 60s minimum (rounds up), so there's
  no sub-minute saving — **use the minute**: cap *connected/post-answer* time at ~**55s**
  (margin below 60s so teardown jitter doesn't roll into a 2nd billed minute). Ring (~30s)
  is pre-answer = free.
- **No free pre-answer shortcut.** You can't `CANCEL` at/after the `200` (answered = billed;
  `CANCEL` is invalid post-final-response); cancelling *during* ringing is free but loses
  the answer time + VM — too weak. So per (premium) block it's binary: **pay one minute**
  (everything; ~$0.24 once even at Palestine rates) **or skip** it and serve generic.

**Rate gating vs. cost recording (two separate sources — don't conflate).**
- **Pre-call gate (decide profile / skip):** needs a rate *before* dialing → the **prefix
  rate deck** (`extras/sip-number-exploration/rates.csv`: canonicalize → longest-prefix
  match). Rates are per-destination-prefix, not per-number, so this is the right shape;
  keep the deck fresh (re-download periodically), or use a Telnyx **rate-deck / outbound-
  voice-profile pricing API** if one exists (programmatic + always-current; *unconfirmed* —
  check docs). The **CDR/webhook cost cannot gate** — it only exists post-call.
- **Post-call record (store actual spend):** the **`call.hangup` webhook** is the clean
  mechanism — with **"Enable call cost"** set on the Programmable Voice Application, each
  hangup payload carries the exact per-call charge (`cost`, `currency`, `duration`,
  `billing_id`) pushed in real time — better than polling CDRs. Store it in `dial_intel`
  per profiled number, and it doubles as **live cost tracking** of the whole live-permit/
  bait spend (per number/actor/experiment). *Prereq:* a webhook endpoint the honeypot
  exposes for Telnyx to POST to (inbound HTTP; the Telnyx side currently sits behind
  Asterisk). The CDR `Rate`/`Cost` fields are the pull-based equivalent if webhooks aren't
  wired.

**Capture: raw callee RTP, not MixMonitor.**
- Use the **raw callee-leg RTP** (`pbx_rtp_dump`, already taken on live-permit calls) —
  byte-stable G.711 → **consistent hash** (the 666.7 Hz fingerprint method) **and**
  re-streamable for replay. One primitive serves both fingerprint-matching and playback.
  MixMonitor (decode→mix→resample→WAV) perturbs the bytes; keep it only for human audit.
- Caveat: byte-hash assumes a consistent codec path; for cross-path matching the robust
  upgrade is an **acoustic/perceptual fingerprint** (transcode-tolerant). Byte-hash = fine
  first cut.
- Per call capture: ring/answer **timing**, **provisional sequence + gaps**, **disposition**
  (answered→VM / reject code `603`/`486`/busy), **raw RTP greeting** (+ its hash).

**Block identification & cohesion (this is the throttle).**
- Detect blocks by leading-digit adjacency (+ carrier / rate-center). Targets come in
  sequential leased blocks on a shared platform/VM ([sip-nanp-line-types-whois.md](sip-nanp-line-types-whois.md),
  [sip-operator-attribution.md](sip-operator-attribution.md) dest-block signal), so the
  profile is usually identical across a block.
- **Profile a representative; validate cohesion** by comparing the VM-audio hash (+
  disposition) of 1–2 more members. Match → mark block cohesive, reuse profile, stop
  profiling new members. Divergence → split out, profile individually. The audio hash does
  double duty (cohesion + matching). Collapses a 200-number block into ~1–2 calls →
  **removes the need for cost rate-gating** (a big new-block sweep = a couple of calls).

**Replay path.**
- Bot dials a profiled number (or a cohesive-block member) → reproduce the **timing** (wait
  the captured ring, emit captured provisionals at captured gaps, then `200`), then play the
  **captured raw RTP greeting** as hold audio — or **mimic the captured reject** (`603`/
  `486`/…). Disposition-mimic also implements the negative-control reject from
  [sip-negative-control-probes.md](sip-negative-control-probes.md).
- **Cold start:** first-ever dial of a brand-new number gets the generic answer (one call)
  while it's profiled in the background for later dials.

**Multi-server deployment — Phase 1 (aggregator-only) vs Phase 2 (fleet sync).**
Fleet context: 8 geo-distributed servers; intel currently aggregates **one-way** (spokes →
aggregator). Profiling wants fleet-global state (de-dup, profiles, claim-lock) that the
1-way design doesn't push back down.
- **Phase 1 — aggregator-only (recommended start).** Run B2BUA + profiling + replay only on
  the aggregator (it already holds the fleet-global `dial_intel`). It profiles *every* new
  number from the combined view — the reference call is outbound, independent of which
  server saw the dial — but **replay runs only on the aggregator**; the other 7 servers
  don't bridge (they **deny**, preferred, or keep their current generic answer). Properties:
  - No 2-way sync, no distributed cache/lock — all profiling state is local to the aggregator.
  - **No load concentration:** deny ≠ forward, so the aggregator bridges only its own traffic.
  - Knock/target/IP intel preserved on all 8 (the knock lands at the INVITE, *before*
    answer/deny); only **post-answer/bridging** behavior is lost on the 7 — which matches how
    we already deep-dive a single server's trace.
  - **Deny is realism-*improving*** on a non-replaying server: a deny looks like a plausible
    non-completing route (real routes vary across IPs), whereas a *mismatching* generic
    answer is exactly the compare-to-real FAS tell. Open knob: **deny** (better FAS-evasion,
    simpler; may earn fewer repeat dials) vs **leave-as-is** generic answer (max engagement,
    keeps the existing tell). The 7 are primarily knock collectors, so either is defensible.
- **Phase 2 — fleet-global intel + hub→spoke push (only if Phase 1 proves out).** Make the
  aggregator the authoritative global `ip_intel`/`dial_intel`/profiles and add a **downward**
  channel pushing distilled, inline-needed state (profiles, profiled-set, bans) to each
  spoke's **local cache**; inline reads stay local (fast, geo-friendly, resilient), eventual
  consistency (cold-start already tolerates propagation lag). Enables **fleet-wide replay**
  plus immediate side-benefits: **global bans** (a flooder on one server blocked everywhere)
  and **combined-threshold auto-ban** (catch distributed low-and-slow that stays under each
  server's per-server `--max-knocks`). The downward channel basically doesn't exist today
  (bans are per-server), so this is real new work — deferred until replay proves worth it.

**Storage / schema — TBD (review each field: meaning + how determined).**
- `dial_intel` (or a new `dial_profile`) keyed by number, with a **block reference** so
  members share one profile.
- Candidate fields (all **TBD**): ring/answer timing (*which* interval — INVITE→200 vs
  180→200?), provisional sequence + inter-response gaps, disposition taxonomy, codec/SDP
  shape, raw-RTP greeting path + audio hash, block key, cohesion status, `profiled_at`,
  source (burner) DID, rate/cost class. **Walk each field before implementing.**

**Guards / caveats.**
- **Burner DID** (OPSEC / PAI — we leak our number to the endpoint).
- **Don't mimic headers** — Telnyx topology-hides the endpoint's, and we control our own
  responses anyway. Replay **timing + audio + disposition** only.
- **Connected-time cap is post-answer** — the B2BUA's existing cap is start-based; profiling
  calls need an "answer + ~55s → BYE" timer.
- **Staleness:** re-profile occasionally; skip garbage / unresolvable dial strings.

---

## Other deferred items (this session)

- **INVITE retransmission (B2BUA→Asterisk, Timer A/B).** Makes a dropped INVITE on the
  remote-Asterisk UDP leg recoverable instead of a lost call. Deferred after the 06-20
  burst — revisit if the intake-rate overload recurs. (Reap + per-IP cap shipped as the
  mitigation; see `sip_daily_observations.md` 2026-06-20.)
- **Per-IP INVITE *rate* limit.** The current `PBX_MAX_BRIDGES_PER_IP` is a *concurrency*
  cap (resource bound), not a rate limit — it doesn't fully bound the INVITE *arrival rate*
  that drove the no-response drops. A token-bucket per IP would. Deferred ("fix if it
  becomes a problem").
- **`b2bua_trace.py`: third `sent` state `stray`.** `sent=engaged` uses a 400-byte
  threshold, so bots that sent 1–399 B of RTP (a few stray/keepalive packets) read as
  `silent`. A `silent`/`stray`/`engaged` split would directly answer "which bots sent *any*
  RTP" (17 such bridges currently hidden, incl. the FR pump + embassy). Reconcile with the
  `media-sent` column (which uses `>0`).
- **Capture session-timer headers per INVITE** (`Supported`, `Session-Expires`, `Min-SE`,
  `refresher`). Read-only; not stored today. Tells us whether the holders even negotiate
  session timers and who they expect to refresh (i.e. whether their silence is correct UA
  behavior or a tell). Prerequisite for "grade UA sophistication" above.
- **Trace blind spot:** an in-dialog re-INVITE *from the attacker* is answered but not
  traced (`sip_b2bua.py:903`). 1-line `trace()` to remove the blind spot.
- **Media-inactivity "challenge mode."** Enforce an RTP-inactivity teardown (drop a held
  call after N s of no inbound RTP) to test which bots defend with keepalive RTP vs just
  redial — the media-channel counterpart to the re-INVITE probe.
- **Analyzer/skill stage lists:** add the new `pbx_no_response` and `rejected` (per_ip_cap)
  stages to `b2bua_trace.py` / the `sip-daily-review` skill stage docs.
- **Source-side RTP-dump capture cap (B2BUA).** `data/rtp_dumps/` grows unbounded from beacon
  IPs that re-stream the same steady tone hundreds of times (one actor was 93% of the dir;
  150 files in a day). Today this is handled *offline* by `extras/sip-number-exploration/prune_rtp_dumps.py`
  (frame-set-hash dedup of stationary tones, keep 2 per (frame-set, IP); guards: pbx, decoded
  RFC2833 DTMF, non-stationary content, review cutoff — 32 MB → 3.3 MB). The cleaner fix is to
  **bound it at capture**: in `sip_b2bua.py`, cap dumps per `(source-IP, modal-frame fingerprint)`
  — stop writing once K byte-identical-fingerprint copies from an IP exist. Keyed on the exact
  fingerprint, so it's classification-free and never risks content; would make the offline prune
  a rare cleanup rather than a recurring need. (Fingerprint = `sip_rtp_triage.fingerprint()` md5.)
- **Durable RTP *timing* capture (prune is timing-blind).** `prune_rtp_dumps.py` dedups by
  audio frame-set, which preserves content but **discards per-packet timing**. Today that's safe
  (held-to-cap holders send no RTP; our dumps are continuous tone beacons — zero keepalives). But
  the day a bot **keepalives a held call** (a repeated token frame sent every N s over a long
  hold — `distinct≈1`, stationary → would be deduped), the keepalive *cadence* — often the whole
  fingerprint — lives only in the `.rtp` timestamps and would be lost on dedup. Fix: capture a
  per-call **RTP timing summary** (packet count, duration, cadence, max inter-packet gap) into the
  durable trace log, so timing survives independent of dump pruning. Pairs with the
  `media-inactivity challenge mode` / keepalive-RTP items above (that's when cadence becomes the
  signal). Optional cheap interim guard: exempt **sparse** files (`fill<0.5` / max-gap >1 s) from
  dedup — the timing-bearing analog of the stationarity gate that already exempts order-bearing
  (DTMF/speech) files.
