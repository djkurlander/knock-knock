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
(same ring time, same VM greeting, same disposition) matches. **Supersedes** the earlier
"answer-realism hardening" idea — replay beats synthesized realism.

**Feature tiers — build the cheap 80% first; treat blocks as a *deferred* optimization.**
The block-cohesion machinery (prefix `dial_block`, predict/confirm, the cohesion state machine)
is a lot of code for a small, bounded payoff: only 16–31% of targets are in blocks, and the thing
it saves — profiling-call cost — is already tiny. Pricing the *whole* current corpus from the cache
rates: **~$37 total** (all 555 numbers, worst-case every one answers for 1 billed minute; really
less — invalids/ring-no-answer don't connect), one-time. Blocks would save only **~$6–12** (16–31%
of $37), and a per-call rate cap (see "Wallet & per-call cap" below) takes even that to **~$4**.
The *real* win is exact-number replay (a held-to-cap target dialed 100× → profiled once, replayed
99×), which needs **no** block logic. So:
- **Tier 1 (MVP): exact-number profile + replay.** `dial_profile(profile_id, …)` + a `number →
  profile_id` mapping (1:1). Captures ~80% of the value (all the repeat-dial volume). No blocks,
  no prefix matching, no cohesion machine.
- **Tier 2 (cheap block reuse — tiny add, optional).** Because numbers and profiles are *already
  separated* (the `profile_id` indirection), block reuse is just: on a new number adjacent to a
  known one, **create its row pointing at the neighbor's `profile_id`** (N:1) instead of profiling
  it — saves the call. Every member keeps its own exact-number row; **no prefix table, no
  longest-prefix, no cohesion state machine.** The only added logic is a simple "is there a
  profiled number near this one?" check on a cache miss. (Optionally confirm the carrier async and
  un-point on mismatch — but even that is optional.)
- **Tier 3 (deferred — the fancier block optimization, build only if it proves useful).** Collapse
  block members to **one** `dial_block` prefix row (instead of one row per member), with
  longest-prefix resolution, the predict/confirm cohesion machine, carrier-confirm, and divergent-
  member splits. This trades real code for fewer rows + auto-covering never-seen members — worth it
  only if per-row volume or profiling cost actually becomes a problem (it likely won't).

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

**Wallet & per-call cap (don't profile the monetization tail).** We're *less* interested in
profiling the high-rate revenue-seeking targets: calling them (a) costs the most, (b) **funds the
fraud** (the revenue-share completes once), and (c) gains little realism — those bots *hold* to
bill minutes, they don't do the compare-to-real audio check that route-discovery/FAS probes do. So
spend the (tiny) profiling budget on the **cheap** targets where realism actually matters, and skip
the expensive ones.
- **`SIP_CALL_MAX`** — per-call cost ceiling, computed pre-call from the **local `rates.db`**
  (`telnyx_rates.lookup` → `rate_per_minute × billed_minutes + price_per_call`; fast, no API).
  Skip profiling any number whose estimated call cost exceeds it. Use **cost (incl. setup fee)**,
  not bare per-minute — catches a high *connect-fee* number (e.g. a UK `0900` `$6.84`/call) that a
  per-minute cap would miss. Measured impact on the current corpus: cap `$0.10` → profile 442, skip
  111 high-rate, spend **~$4** (vs $37 uncapped); the skipped 111 are exactly the African/Cuba/
  premium-mobile IRSF tail.
- **Wallet = a Redis purse balance, topped up by a tool — not an `.env` value.** The remaining
  balance lives in **Redis** (`knock:sip:wallet`, a float); each outward call gates on
  `balance ≥ estimated_cost`, then **decrements** it; at ~0, **no outward calls** (so a fresh/empty
  wallet means profiling is *off* until funded — safe opt-in). Keeping it in Redis means it
  **persists across `./restart.sh`** — the trap with an `.env` budget is that a restart would refill
  it; a Redis balance doesn't. (Same Redis-state shape the live-permit active-lock uses.)
- **`sip_add_funds.py`** (in `extras/`) sets or adds to the purse: `--set 50` / `--add 10`. Manual
  top-up; no built-in period logic. **Want a daily allowance? Put it in crontab** — e.g.
  `0 0 * * * sip_add_funds.py --set 5` — so the *policy* (cadence, amount, reset-vs-accumulate) is
  the operator's, not baked into the honeypot.
- **Estimate to gate, ground-truth to account:** gate on the `rates.db` estimate (pre-call),
  then **decrement the wallet by the *actual* cost** from the `call.hangup` webhook when it lands
  (fall back to the estimate if the webhook isn't wired).

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
- **Where these come from — two layers, split by the false ACK.** On a live bridge,
  `sip_b2bua._handle_pbx_response` **relays** the real target's responses to the bot
  (`180/183/200/486/404/603`; only `100` is suppressed), so:
  1. **Bot-facing `sip_result` = the relayed final response** — *not* the synchronous `200`
     placeholder set at INVITE time (`sip_honeypot.py:859`, which just means "decided to
     bridge"). For live calls record the **real relayed final code** (busy/declined/answered)
     as `sip_result`, **async-UPDATEd** when the call resolves, sourced from `_handle_pbx_response`'s
     `code` on the `≥200` final. (Non-live calls: the local `200` placeholder is already correct.)
  2. **Callee-leg capture — decoupled by the false ACK.** On a `2xx`, for `live_permit` calls the
     B2BUA self-ACKs the PBX leg *regardless of whether the bot ACKs* (`pbx_early_ack`), so that
     leg stays up and we record the callee's RTP/VM + answer timing **even after the bot's silent
     abandon**. This is the profiling payload (above), captured on our schedule and aggregated into
     per-number `dial_intel` — a layer the bot's behavior can't deny us. **Only exists on `2xx`**
     (answered); `4xx`/`6xx` close the bridge → signaling-only, no callee leg to keep alive.

**[TIER 3 — DEFERRED] Block identification & cohesion (the *fancier* optimization).** Skip for the
MVP; this is the prefix-collapse/cohesion machinery from the Feature-tiers note. The cheap Tier-2
alternative — point a new adjacent number's row at an existing `profile_id` — needs none of the
below (no synchronous predictor, no carrier in real time, no cohesion state machine).

Note on the carrier signal (applies to *any* tier that uses it): the **synchronous decision is
number adjacency/proximity only** — at INVITE time we don't yet have the *new* number's carrier,
and knowing the block's carrier doesn't qualify the new number (a match needs *both*). Carrier is a
**confirmer**: either (a) look it up quickly in the `100 Trying` window (~185 ms, timeout +
fallback) to confirm before reuse, or (b) **punt** — reuse on adjacency, look the carrier up async,
and un-point/split on mismatch (preferred: keeps the SIP hot path clean). Use the **dialed-number
carrier/OCN (+ rate-center), NOT source ASN** — ASN is the attacker's hosting (operator
attribution), the wrong axis for target-block cohesion.

The full predict/confirm machinery, if Tier 3 is ever built:
The trap: confirming a block truly needs ≥2 members' data (post-hoc), but the **throttle
decision** (call this new number, or reuse a profile?) must be made *synchronously at first
sight* — else you've already called everything and the throttle failed. The fix is that the
*predictor* is cheap and needs **no call**, while the slower *confirmer* runs async and only
corrects.
- **Predict (synchronous, at first sight, NO call → drives call-vs-reuse).** Two cheap signals:
  (1) **digit adjacency** — is the new number within a few of / sharing a prefix with an
  already-profiled number? Pure arithmetic, instant. (2) **carrier / rate-center match** — from
  the **Telnyx number-lookup cache** (a hit is free; a miss is one ~fraction-of-a-cent *lookup*,
  not a call). Match → **eagerly attach to that block's profile and REPLAY — no call** (and
  promote a `/1`→`/10` `dial_block` entry covering both; that promotion *is* the moment you skip
  the new member's call). No match → unprofiled → profile it (one call), seed a tentative block.
- **This is optimistic** (reuse without verifying the new member's VM), justified because the
  *population* is sequential leased blocks on a shared revenue-share platform — empirically VM/
  disposition-identical ([sip-nanp-line-types-whois.md](sip-nanp-line-types-whois.md),
  [sip-operator-attribution.md](sip-operator-attribution.md) dest-block signal). So
  adjacency+carrier is a *strong* cohesion predictor *for these targets* (weak for random
  consumer numbers — irrelevant here). Downside of a mispredict is low: per the "no header tell"
  finding a wrong VM isn't detectable in-band (only via the operator's own out-of-band inbound
  check).
- **Confirm (async / sampled — validates, does NOT gate the throttle).** Occasionally re-profile
  a block member and compare its **VM-audio hash** + disposition to the block profile. Match →
  mark `cohesive` (keep reusing). Divergence → split the outlier out (a `/1` override at its full
  number). The audio hash does double duty (cohesion + cross-path matching). Net cost ~**1 seed
  call + a couple of async confirmation calls per block, regardless of block size** → collapses a
  200-number block into a handful of calls, **removing the need for cost rate-gating**.

**Replay path.**
- Bot dials a profiled number (or a cohesive-block member) → reproduce the **timing** (wait
  the captured ring, emit captured provisionals at captured gaps, then `200`), then play the
  **captured raw RTP greeting** as hold audio — or **mimic the captured reject** (`603`/
  `486`/…). Disposition-mimic also implements the negative-control reject from
  [sip-negative-control-probes.md](sip-negative-control-probes.md).
- **Cold start:** first-ever dial of a brand-new number gets the generic answer (one call)
  while it's profiled in the background for later dials.

**Replay engine design — one dialog engine, two back-ends — 2026-06-26 design pass.**
- **Per-number state machine:** `UNPROFILED → PROFILING → PROFILED`. Gated by
  `SIP_DIAL_PROFILE`. First bot dial of an `UNPROFILED` number → issue a one-time
  `sip_live_permit` (`max_calls=1`, burner DID) and **live-bridge that call** to capture (the
  permit system *is* the bounded-completion control — don't bypass it). Subsequent dials of a
  `PROFILED` number (or cohesive-block member) → **playback**.
- **Architecture — reuse the bot-facing engine; *don't* build a standalone playback B2BUA.** The
  `Bridge` class already separates the two halves cleanly, so playback is a **back-end swap**, not
  a reimplementation — the elegant framing is *one dialog engine, two sources*:
  - **Shared bot-facing dialog engine** (reused verbatim): the injected `send_to_attacker`
    callback, the RTP sender (`_silence_loop` is *already* a generative toward-the-bot media path —
    playback feeds recorded frames where it feeds silence), `forward_in_dialog` / ACK·CANCEL·BYE
    handling, `close` / `_timeout_loop`, `_open_rtp_dump`, SDP localization. Bot-facing SIP + RTP +
    teardown are identical for a live bridge and a replay.
  - **Pluggable back-end (the *source* of responses + media):** `LiveSource` = today's Asterisk
    relay (`_sip_loop` / `_handle_pbx_response`); `RecordedSource` = `b2bua_playback` (a timed
    schedule + RTP-dump reader). Same dialog, same RTP sender, same teardown — only the source
    varies. Implement as a `PlaybackBridge` (subclass or a `source=` strategy on `Bridge`).
- **Playback ≈ `Bridge − live-PBX-leg + timeline cursor` — i.e. *simpler* than a real bridge.** It
  **drops** the hairy parts (live second socket/`_sip_loop`, the glare race, the false-ACK to
  Asterisk, PBX-BYE handling) and **adds** only a sorted `[(t_ms, code)]` schedule + a timer that
  calls the existing `send_to_attacker(build_response(code))`, then feeds recorded RTP through the
  existing sender. Asterisk is bypassed on replay (no real call); Asterisk-dialplan replay is
  rejected (coarse timing + re-encoded WAV). B2BUA-native `RecordedSource` = precise timing +
  byte-exact RTP + zero real call.
- **`b2bua_playback.py` = the `RecordedSource` component** (profile load, event scheduler,
  RTP-frame reader), *driven by* the Bridge — file-level separation of the playback-specific logic
  without duplicating the dialog/RTP machinery. It emits each recorded response at its `t_ms`
  offset, **subject to the bot's protocol participation**: bot `CANCEL` before our `200` → stop;
  bot `ACK`s → proceed with RTP; bot never ACKs (silent abandon) → hold/teardown per the recorded
  window. Non-`2xx` disposition → emit the recorded reject (`486`/`404`/`603`) at its captured
  timing (also subsumes the [sip-negative-control-probes.md](sip-negative-control-probes.md) reject).
- **Capture side = a few lines in the existing `_handle_pbx_response`** (which already traces
  `pbx_response code=X` with a timestamp): append `(t_ms_since_invite, code)` to the profile's
  event list, plus the `-pbx.rtp` dump already written for live calls. No new subsystem — the
  `LiveSource` path *is* the recorder.
- **The "op recording" — what the captured profile actually is.** Almost exactly your
  `[(delay, code), …]` intuition, because on replay the engine *regenerates* the response (see
  "no header tell" above): Via/From/To/Call-ID/CSeq are echoed from the **live** bot INVITE,
  `Server` is hardcoded, the SDP ip/port are **localized** — so none of those are recorded. You
  record only what **varies and can't be reconstructed**: the **timing**, the **status code**
  (the "op": 100/180/183/200/486/404/603), and on a media-bearing response the **codec** + an
  **early-media marker** (a `183` *with* SDP means RTP starts there, not at `200`). The reason
  phrase is derivable from the code (capture the literal only for byte-fidelity on a custom
  carrier reason). The bot's own messages (INVITE/ACK/CANCEL/BYE) are **not** recorded — they
  arrive live and are handled reactively; the recorded timeline is **responses only**, anchored
  at the live INVITE.
- **Profile schema** — small timed-event JSON + the separate raw `.rtp`:
  ```json
  { "disposition": "answered|busy|invalid|ring_no_answer",
    "events": [ {"ms":0,"code":100}, {"ms":1200,"code":180},
                {"ms":4800,"code":200,"media":{"codecs":["PCMU"]}} ],
    "final_code": 200,
    "rtp": { "ref": "…-pbx.rtp", "payload_type": 0, "starts_at": "code:200" } }
  ```
  The `events` array is the timed signaling re-enactment; `rtp.ref` points at the ~minute of
  callee audio (stored as a **file**, not inline — see storage below). Timing is the point —
  capture *when* each step happened, not just *that* it did.
- **Gotchas (where naïve "replay the recording verbatim" breaks):**
  - **SDP is localized, not replayed** — regenerate the B2BUA's own SDP (its RTP port) so the
    bot streams to/from us; replay the *timing*, not the callee's endpoint. (Same as the bridge's
    `build_sdp` today.)
  - **RTP headers regenerate; only payloads replay** — fresh seq/timestamp/SSRC (a continuous
    stream from us), recorded *payloads* inside. Same machinery that mints relay/silence RTP.
  - **Codec must match** for byte-exact audio (bots ~always offer PCMU/PCMA → fine; else
    transcode and lose byte-exactness, or decline).
- **Detectability (verified 2026-06-26): there is NO in-band header tell.** `_build_inbound_response`
  already regenerates the bot-facing response entirely — `Via/From/To/Call-ID/CSeq` echoed from
  the bot's request, `Server: Asterisk PBX 18.0.0` hardcoded, SDP localized. The bot's dialog
  terminates at *our* stack (back-to-back UA) on a real bridge **and** on replay, so the only
  downstream-derived signals are **status code/reason, timing, and RTP** — exactly the three the
  profile reproduces. So replay is **header-identical to a real bridge.** Residual tells are NOT
  headers: (1) **media too-consistent** — byte-identical VM every call (a real VM varies per call);
  mitigate with slight per-call variation / a couple of samples; (2) **timing too-consistent** —
  add small jitter around the recorded offsets; (3) **out-of-band:** the *target operator's own
  inbound records* (for revenue-share numbers they control) — "I dialed through the PBX, did my
  number actually ring?" never true on replay. There's no bot-side carrier CDR (it connects direct
  to :5060), so the upstream-CDR concern doesn't apply; the operator-inbound check is the one
  unbeatable-in-band detection.

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

**Storage & delivery — 2026-06-26 design pass.**
- **[TIER 1/2] Separate numbers from profiles — that indirection is the whole game.**
  - **`dial_profile(profile_id PK, events_json TEXT, rtp_ref, codec, disposition, captured_at,
    audio_hash, …)`** — the actual profiles. **Never inline the profile per-number** (would
    duplicate the JSON + RTP ref across members).
  - **`number → profile_id` mapping** — an exact-number map (its own table, or a `profile_id`
    column on `dial_intel`). **Tier 1:** each number → its own `profile_id` (1:1). **Tier 2 (cheap
    block reuse):** a new adjacent number's row just **points at an existing `profile_id`** (N:1) —
    multiple exact-number rows, one shared profile, no extra schema. Lookup is a plain **exact-
    number** read (fast, no prefix matching).
- **[TIER 3 — DEFERRED] `dial_block(prefix PK, profile_id, cohesion_status, member_count, …)`** —
  *only* if you later want to collapse a block to one row instead of one-per-member. Keyed by a
  **digit prefix** (full-E.164 = individual/override; shorter prefix = shared block), resolved by
  **longest-prefix match** (reusing `telnyx_rates.lookup()`'s `[digits[:n] for n in …]` → `WHERE
  prefix IN (…) ORDER BY len DESC LIMIT 1`). Lets a short prefix cover never-individually-dialed
  members. **Caveat:** prefix entries model power-of-10-aligned blocks (how DIDs lease —
  `+9723375135x`, `+44203807xxxx`); add `(low,high)` ranges only if a non-aligned lease appears.
  Tier 1/2 don't need any of this — exact-number rows suffice.
- **Event list = JSON `TEXT`** (small, structured, travels with the DB). **RTP = a referenced
  *file*** (the `-pbx.rtp` dump), not an inline `BLOB`/base64 — hundreds of KB shouldn't ride
  every profile query. Tradeoff for later: **Phase 2** fleet-sync then needs a small file-push
  channel for the audio (vs. a blob that rides DB sync); start file-ref, revisit if Phase 2
  makes blob-for-sync worth it.
- **Delivery is an *in-process lazy-load*, not a wire send.** The B2BUA is the `PlaybackBridge`
  *class inside the SIP honeypot process* (which already opens the DB to seed the dial cache).
  On a `PROFILED` INVITE: look up `profile_id` → `json.loads(events_json)` + open the `rtp_ref`
  file → construct `PlaybackBridge(source=RecordedSource(...))`. Lazy-load + LRU-cache recent
  profiles (don't preload all — the RTP makes that heavy). The JSON-ify ↔ parse happens only at
  the **storage boundary**, not as a message to a separate process. The only place a profile is
  genuinely *shipped* is Phase-2 fleet replay (aggregator → spokes), which is the deferred
  hub→spoke push.
- Candidate `dial_profile` fields (walk each before implementing): ring/answer timing (*which*
  interval — INVITE→200 vs 180→200?), the timed `events` (provisional sequence + inter-response
  gaps), disposition taxonomy, codec + early-media shape, `rtp_ref` + audio hash, `block_ref`,
  cohesion status, `captured_at`, source (burner) DID, rate/cost class.

**Build order — hub-first (this server is the aggregator).**
- **v1: single-server, on the aggregator only** (= this box). Capture + `dial_profile` + replay
  all local; this is exactly **Phase 1 (aggregator-only)** above, so no fleet sync, no hub→spoke
  push, RTP stays a local file. Prove capture fidelity + replay indistinguishability + block
  cohesion here first.
- **v2: extend to spokes/feeders** — only after v1 proves out, add the **Phase 2** hub→spoke push
  (distill `dial_profile` rows + ship the RTP files to spoke local caches) so replay runs fleet-wide.
  That's the real new work (the downward channel doesn't exist today); defer until v1 earns it.

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
- **Analysis: are the bots adaptive? (dialplan-restriction natural experiment).** LA1's
  `SIP_OK_DIALPLAN` was changed **`all` → default (`+,bare,00,011,9`)** at the monitor restart
  **2026-06-25 18:57:32 UTC** — a clean before/after **changepoint** on one server. The **other
  servers were already restricted** (no `SIP_OK_DIALPLAN` env = default), so they're a built-in
  control. Under `all`, weird dial-out prefixes all got `200`; now they `404`. Question: **do the
  flooders adapt** — after their non-standard prefixes start failing, do they shift toward the
  accepted set (`+/bare/00/011/9`), or replay the same fixed prefix list regardless? E.g.
  `108.181.63.2` was flooding `[39xxx-counter]0016823074942` (all `404` now); `144.172.109.53` runs
  a fixed `0/00/9/810/011/012/015/…` sweep. **Method:** per-actor accepted-prefix *share* of dial
  strings, LA1 **before vs after 18:57 UTC 06-25**, cross-checked against the **always-restricted
  servers** (if bots adapt, accepted-share rises post-changepoint on LA1 and is already higher on
  the control servers; if not, weird-prefix volume persists unchanged). **Why it matters:**
  distinguishes **closed-loop probers** (react to `404`s — sophisticated) from **dumb replay bots**
  (fixed dial list) — informs bait strategy and operator attribution. Run after the bots have had a
  few days to react (≥ ~1 week post-changepoint, so ~2026-07-02+). **Data note:** `sip_result`
  (200/404) is now stored in `knocks_sip` going forward (added 2026-06-25, populated after each
  server's next restart) — use it directly for post-change rows. For **historical rows (NULL** —
  pre-change) and for the pure prefix-acceptance signal, recompute per row from the stored
  `sip_dial_string` via `sip_honeypot._dialplan_accepts()` (deterministic; note recompute gives
  `dialplan_ok`, which differs from stored `sip_result` only in the rare live-permit/bridge-override
  cases).
