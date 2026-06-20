# SIP daily observations

Running log of notable SIP / B2BUA honeypot observations, newest first. Quick
field notes — promote anything that grows into a full investigation to its own
`sip-<topic>.md` note.

---

## 2026-06-20

### Observations since 2026-06-20 05:42 UTC, LA1

- **New sustained French monetization pump — `37.187.144.149` → `+33972307742`.** OVH
  (AS16276), single IP / single target, dialing since 06-15 (~2,000 INVITEs). This window:
  **233 ACK + hold-to-1200s-cap** (ACK ≈5 s, `ACK+BYE` teardown) — the dominant holder,
  ≈78 h of held time in ~11 h. From-user enumerates extensions (`101/111/1011/2000/…`);
  SDP `0.0.0.0` → `not-listener`. Not in the IPRN harvest; rate/payout TBD (`+33 9` is
  French non-geographic). Full profile: [sip-37187-fr-pump.md](sip-37187-fr-pump.md).

- **Asterisk stress event ~11:49–12:08 UTC under the FR-pump load.** 20 embassy
  (`209.222.101.54` → `+12022234942`) INVITEs got **no PBX response at all** and squatted
  the **full 1200 s cap** as zombie bridges (`started` → `timeout`, no `100/183/200`),
  plus **13× `488 Not Acceptable Here`**. No RTP-pool exhaustion (`setup_failed=0`). The
  embassy bot did **not** start holding — these are stuck no-response bridges. *Possible
  reap bug:* a bridge that never gets a PBX response should be torn down fast, not ride the
  1200 s cap tying up relay ports.

- **Listener instrumentation's first real yield: 229 `rtp_unreachable`, and the first
  `cls=global` actors.** `153.75.90.249` → `+33756758573` advertises a **real public media
  endpoint** (`132.185.229.16:8000`) — 9 `possible` / 19 bounced; `192.210.236.35`
  (HostPapa, IT+US) and `160.119.71.111` (IT) also `cls=global`. The embassy stays
  `not-listener` (`cls=private 192.168.1.83:25282`, 90 bounces). The `possible` verdicts
  are the first "could-be-listening" cases since instrumentation went live.

- **Multi-source pumping of the Transatel `+33756758573` continues.** `153.75.90.249`
  (RouterHosting, AS14956) is a co-source alongside `107.189.20.125` — and is the first
  *monetization* actor advertising a routable media address (`cls=global`).
  [sip-107189-cli-counter.md](sip-107189-cli-counter.md).

### Infrastructure changes (B2BUA resilience)

Fixes / mitigations for the zombie-bridge / Asterisk-overload exposure flagged above
(`sip_b2bua.py`, **pending B2BUA restart**):

- **No-response reap** (`PBX_NO_RESPONSE_SECONDS`, default 10 s): a bridge the PBX never
  responds to is torn down at ~10 s (`stage=pbx_no_response`) instead of squatting its RTP
  ports to the 1200 s cap. Asterisk `100`s instantly, so zero response = a dropped INVITE
  on the remote-Asterisk UDP leg. (Fully fixes the zombie/port-squat part.)
- **Per-IP concurrent-bridge cap** (`PBX_MAX_BRIDGES_PER_IP`, default 25): bounds how many
  concurrent bridges one IP can hold (RTP pool + Asterisk channels). Over-cap INVITEs aren't
  bridged (`stage=rejected reason=per_ip_cap`); the honeypot answers them normally (no 486
  tell) and the knock is still recorded. `live_permit` exempt. Retroactively covers the
  06-17 York RTP-pool exhaustion class. **Note:** this is a *resource* cap, not a rate
  limit — during ramp-up Asterisk can still see up to ~25 rapid INVITEs, so it mitigates
  but doesn't fully bound the INVITE *arrival rate* that drove the no-response drops.
- **Root cause:** a ~4-min, ~35× INVITE burst (44→71/min) from the FR pump + embassy at
  11:49–11:52 UTC overran the remote-Asterisk UDP leg; ~35% of INVITEs got no response, and
  the single-shot (no-retransmit) INVITE turned each drop into a 20-min zombie.
- **Known residual gap (deferred):** the intake-*rate* overload itself isn't fully solved.
  A per-IP INVITE **rate limit** and/or **INVITE retransmission** (Timer A/B, makes drops
  non-fatal) were considered and deferred — revisit if it recurs.
- **For future trace reads:** post-restart, expect new stages `pbx_no_response` and
  `rejected reason=per_ip_cap`.

### Infrastructure changes

- **B2BUA media-reachability instrumentation.** Added two per-bridge traces plus a
  listener verdict to answer "does the callee/bait audio we relay actually reach a
  consumer?": `stage=sdp_media` (the RTP endpoint the bot advertised + a reachability
  class — `global`/`private`/`unspecified`/…) and `stage=rtp_unreachable` (our relay drew
  an ICMP port-unreachable — nobody on that port; captured via `IP_RECVERR`, so **no probe
  traffic and no wire footprint** — undetectable to the bot). Roll-up + verdict
  (`listener`/`possible`/`not-listener`/`unknown`) in `b2bua_trace.py --listeners`, also a
  column in `--completions`. Observe-only, Linux-gated (`MSG_ERRQUEUE`), no realism cost.
  See `extras/sip-b2bua-trace/`.

### Observations since 2026-06-18 19:41 UTC, LA1

- **Albanian embassy bot — current visitor status.** The dominant ReliableSite actor
  `209.222.101.54` → `+12022234942` is in a new **extension-enumeration phase**: `From=<ext>`
  rotates a candidate-extension wordlist (`8548, 419, 9300, 4501, …`; PBX ranges
  `1xx`/`2xx`/`4xxx`/`9xxx`) in a tight **2-call cycle** — bare `12022234942`, then
  `9+`→`912022234942` — then a new ext. Verified 60/60 bare-vs-`9+`, exactly 2 calls/From.
  Reads as **dial-plan / class-of-service mapping**, a step beyond bare answer-supervision
  (the earlier `00…`/`011…` prefixes are gone this phase). **Measured `not-listener`:** every
  call advertises a fixed RFC1918 media endpoint `192.168.1.83:25282` (`cls=private`,
  `sig_match=False`), never ACKs, sends no RTP/DTMF — the call-tree bait is **for naught**
  for it (first *measured*, not inferred, confirmation). **Self-caps at ~32 s** (SIP Timer H),
  not our cap: the non-live leg isn't self-ACKed, so Asterisk Timer-H's the un-ACKed `200`
  and BYEs (`pbx_bye`). Full profile folded into [sip-embassy-beacons.md](sip-embassy-beacons.md).

- **New Palestine-mobile monetization burst.** `153.75.90.249` (RouterHosting, AS14956) →
  `+970567209720` held **28 calls ACK + to the 1200 s cap** overnight (`23:14`→`02:04`,
  06-19→20), then stopped. Highest-cost cluster (~$0.2422/min, per
  [sip-intl-clusters-cost.md](sip-intl-clusters-cost.md)); same ASN as the `107.189`
  Transatel actor.

- **`107.189.20.125` Transatel pump continues** → `+33756758573` (French mobile): 10 more
  holds-to-cap, metronomic, interleaved with the Palestine holds.
  [sip-107189-cli-counter.md](sip-107189-cli-counter.md).

- **Two high-volume no-ACK floods (route/answer-supervision, not holds).** `185.213.155.237`
  (31173 Services AB, AS39351 — same org as the Jun-17 York flooder) → `+14109839432`
  (Maryland) **2000× in ~54 min**; `185.243.5.118` (ReliableSite, AS23470) → `+15108929741`
  (California 510) 2000× as a slow ~26 h drip. **No RTP-pool exhaustion this period** despite them.

- **Listener verdict validates the media-probe split.** The known 666.7 Hz actors
  `172.110.223.203` (ab00day) and `51.38.52.76` (OVH) classify **`listener`** (engaged —
  sustained inbound RTP), cleanly distinct from the embassy/floods (`not-listener` /
  answer-supervision). First quantified separation of media-probe vs answer-supervision
  actors. [sip-media-presence-probes.md](sip-media-presence-probes.md).

- **`77.42.86.8` (the settled concurrency pump) silent** since the cutoff.

### Re: the 2026-06-18 planned experiments

- **`PBX_ABANDON_SECONDS=60` is moot for no-ACK probes.** Timer H tears the un-ACKed leg at
  ~32 s, *before* the 60 s abandon window — so the "catch late ACKs out to 60 s" test can't
  observe anything past ~32 s (no `attacker_ack age>30` seen). Actually extending a no-ACK
  call would require self-ACKing the non-live Asterisk leg, which is itself an unrealistic tell.

---

## 2026-06-18

### Observations since 2026-06-17 22:13 UTC, LA1 only

- **`77.42.86.8` looks like a settled monetization / concurrency pump, not route
  discovery.** On LA1 (`source=0` / `SOURCE_ID=LA1`), it produced `102` bridged
  SIP rows across only **4 normalized destinations** and **8 raw dial strings**:
  two dial-out forms per number (`00...` and `900...`). B2BUA trace confirms `50`
  completed calls: all sent `ACK`, none sent `BYE`, and all rode the `1200s`
  `b2bua_timeout` cap. Peak confirmed concurrency was `50`. The destination rates
  are not high in `rates.csv`; the signal is duration and parallelism, not a high
  per-minute tariff. The paired / near-paired targets (`+442080890189/190`,
  `+97233751349/351`) look more like owned or allocated endpoints than random
  victims. Full note: [sip-7742868-concurrency-pump.md](sip-7742868-concurrency-pump.md).

- **No embassy dialing seen since the diary mtime.** Checked normalized and raw
  dial strings for Albania `+12022234942`, France `+12029446000`, Saudi
  `+12023423800`, and Britain `+12025886500`; no hits on LA1 or the broader DB
  since `2026-06-17 22:13:33 UTC`.

- **Large no-ACK answer-supervision wave from `193.181.46.158`.**
  `193.181.46.158` (Arelion Sweden AB / AS1299) dialed one Georgia NANP target
  `+12295989162` exactly `2000` times using `30` dial strings. B2BUA trace shows
  these as `attacker_no_ack`, not holders. Peak per-IP concurrency was about `12`.
  This is high-volume route / answer-supervision probing, not a monetization hold.

- **Known 666.7 Hz media-presence probe continues.** RTP triage over LA1 dumps
  since the cutoff found `43` dumps and `42` carry the known `980b7e2c90` /
  `666.7Hz` one-frame toolkit signature, from `172.110.223.203` and
  `51.38.52.76`. One additional single-file non-tone fingerprint appeared from
  `217.154.196.179` to `+442038077708`.

### Planned experiment / instrumentation

- **Raise no-ACK cleanup window for one day.** Temporarily set
  `PBX_ABANDON_SECONDS=60` to test whether any answer-supervision probes send
  very late `ACK`s after the usual ~30s SIP no-ACK window. Watch for
  `stage=attacker_ack age>30`, resource occupancy, and whether late ACKs
  transition into `b2bua_timeout` or `attacker_bye`.

- **Split-leg Asterisk recordings for recipient-audio checks.** On the Asterisk
  server, start recording separate receive/transmit legs (`rx` / `tx`) for bridged
  calls, then run energy / silence detection on the far-end leg. Goal: determine
  whether the destination endpoint sends any non-silence audio during
  monetization-shaped holds, without relying on mixed recordings or manual
  listening.

---

## 2026-06-17

### Infrastructure changes
- **Dedicated durable trace log.** B2BUA `trace()` lines now tee to
  `data/b2bua_trace.log` (`PBX_TRACE_FILE`), with an ISO-8601 timestamp per line,
  written straight from the source — independent of the systemd journal's
  size-capped ring buffer. This is the system-of-record going forward; query it
  (not `journalctl`) and analyze with `extras/sip-b2bua-trace/b2bua_trace.py`.
  Note: the journal only holds B2BUA traces from **Jun 14 03:04** onward — before
  that the prefix was `SIPB2BUA`, which didn't match monitor's `*TRACE` passthrough
  and was dropped; the rename to `SIPTRACE component=b2bua` is what started capture.
- **Embassy bait audio wired up.** The four DC embassy DIDs are now directed in the
  `[honeypot-inbound]` dialplan to **embassy-specific call-tree recordings played on
  a loop** (replacing the default `silence90`), selected by `${EXTEN}`:
  Albania `+12022234942`, France `+12029446000`, Saudi `+12023423800`,
  Britain `+12025886500`. All other session behaviour (headers, `MixMonitor`,
  answer, hold-to-cap, timeout) is unchanged. Purpose: test whether the
  answer-supervision beacons engage (ACK / hold longer / send DTMF / return) once
  realistic audio is present. DTMF responses are captured via `stage=attacker_info`
  (SIP INFO) or the RTP dump (in-band / RFC2833). See
  [sip-embassy-beacons.md](sip-embassy-beacons.md).

### Observations (from the B2BUA log review, last 24–48h)
1. **Monetization (ACK + hold to the 20-min cap) is now active — but on
   France / Argentina / Spain, not the Palestine mobiles.**
   `107.189.20.125` (NL, RouterHosting, AS14956) — the
   [sip-107189-cli-counter.md](sip-107189-cli-counter.md) Transatel actor — is
   still pumping `+33756758573` and has **added a Spanish target `+34902561521`**
   (~90 dials, holding to cap). A new heavy pumper `172.110.223.197` holds
   `+541139876436` (Buenos Aires) to the 1,200 s cap ~50×.
2. **The ab00day operator runs monetization from a sibling IP.**
   `172.110.223.197` (Argentina, ACK+hold-to-cap) and `172.110.223.203` (the
   [sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md) UK media-probe) are
   the **same org** — `isp="Husam A. H. Hijazi"`, AS47154, adjacent in
   `172.110.223.0/24`. So the ab00day beacon actor also runs a full hold-to-cap
   pump next door.
3. **RTP pool exhaustion from a single flooder.** `185.195.232.162` (UK,
   "31173 Services AB", AS39351) dialed one York number `+441904911031` **~2,000×
   in ~7 minutes** (09:57–10:04), exhausting the B2BUA relay port pool → **708
   `no RTP relay ports available` setup failures**. Collateral: other bridges
   (possibly monetization ones) failed to set up during the burst. Mitigation
   ideas: larger RTP pool, per-IP concurrent-bridge cap, shorter no-ACK teardown.
4. **A NANP/embassy number got a real completion.** `47.187.50.45` (US,
   **Frontier residential**, AS5650) → `+12023423800` (**Saudi embassy**): ACK at
   5.2 s, BYE at 15 s, silent (no RTP dump). It's the **only `ack_then_bye` to an
   embassy** in the window — behaviourally the best candidate for an
   audio-validating probe (commit → brief listen → clean release), distinct from
   both the no-ACK beacons and the cap-holding pumpers. Audio-validation is
   *unconfirmed* (all ACKers are silent inbound; we can't see whether it reacted
   to our audio). This is what motivates the embassy bait above — if a
   Frontier-type actor changes behaviour once real audio plays, that's the
   confirmation the silent dumps can't give.

Bonus (surfaced by `b2bua_trace.py`): `+12132610503` (Los Angeles, NANP), source
`51.38.52.76` (OVH), was *streaming inbound audio* — unusual vs the silent norm.

5. **Resolved → the ab00day 666.7 Hz beacon is a shared toolkit signature.** All
   21 `+12132610503` dumps are a single looped G.711 frame (`TONE(1-frame)`,
   autocorrelation lag 12 → 666.7 Hz). The frame is **byte-for-byte identical** to
   ab00day's — both `md5 980b7e2c90`. A sweep of `data/rtp_dumps` found this exact
   frame from **two source IPs only**: `172.110.223.203` (ab00day, AS47154 → UK
   `+442039960320`) and `51.38.52.76` (OVH, different ASN → US `+12132610503`).
   Identical frame across two networks/targets ⇒ **shared tooling** more likely
   than one operator (different campaign/infra not excluded). Fingerprint by the
   frame hash `980b7e2c90` or the 666.7 Hz lag-12 single-frame test — it's
   ASN-agnostic. Details folded into [sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md)
   and [sip-media-presence-probes.md](sip-media-presence-probes.md).

### Logged leads (not yet investigated)
- **Second multi-IP modal-frame signature `042891e750`.** The new
  `sip_rtp_triage.py --fingerprint` sweep flagged a second identical-frame-across-IPs
  signature besides the 666.7 Hz beacon: `md5 042891e750` from `172.232.40.55` and
  `31.70.86.130`, both dialing UK London (`+442038072087`, `+442038076721`). `freq
  n/a` (not a clean tone — only 2 dumps, likely a short/keepalive-style frame, not
  the beacon). Also note `31.70.86.130` shares a `/24` with single-IP `31.70.86.142`
  (`b1f189f4d1`). Worth a look later: what the frame is, who the two IPs are, and
  whether it's another shared tool. Re-find with
  `python extras/sip_rtp_triage.py data/rtp_dumps/ --fingerprint`.
