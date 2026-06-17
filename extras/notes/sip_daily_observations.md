# SIP daily observations

Running log of notable SIP / B2BUA honeypot observations, newest first. Quick
field notes — promote anything that grows into a full investigation to its own
`sip-<topic>.md` note.

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
