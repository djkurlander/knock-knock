# Investigation Notes

Field notes from honeypot bot investigations — one self-contained note per
investigation. When starting a new one, add a file here and a row to the index
below.

**Naming:** `<protocol>-<campaign-or-topic>-<key>.md` (e.g. `sip-ab00day-audio-beacon.md`).
Keep each note self-contained: background, data tables, method, and verdict, so
it can be read on its own.

## Index

| Note | Protocol | Subject | Status | Dates |
|------|----------|---------|--------|-------|
| [sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md) | SIP | Does the `ab00day` bot (`172.110.223.203`) encode an identifier in its post-answer tone? **No** — it loops one fixed G.711 frame; it's an answer/media-presence probe tone. | Resolved | 2026-06-12 → 13 |
| [sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md) | SIP | Bait monetization (phase 2): present one bot a clean, durable, E.164-only completing route + sticky hold + ban-exemption + holdtime logging; watch for discovery→exploit escalation. | Planned | 2026-06-13 → |
| [sip-107189-cli-counter.md](sip-107189-cli-counter.md) | SIP | `107.189.20.125` dials one fixed French mobile (`+33756758573`) with a monotonic ~8.4k/sec counter in the caller ID, and **completes (ACK) + silently holds** — now 16× to a 20-min cap. Target carrier **Transatel** (IRSF-favored range) + sustained multi-source pumping ⇒ holds are **monetization-shaped** (not distinguishable from verification); CLI mismatch is **not** a bait tell (privacy mode is normal PBX behavior). | Open | 2026-06-14 → |
| [sip-embassy-beacons.md](sip-embassy-beacons.md) | SIP | Multiple independent toolkits dial four DC foreign-embassy numbers (Albania/France/Saudi/Britain) as 24/7 "always-answers" route-reachability beacons — answer-supervision, then abandon. Dominant actor: ReliableSite ASN 23470 hitting 3 of 4 from shared IPs. The honeypot never calls the embassy; a real vulnerable route would (modulo FAS). | Ongoing | 2026-06-14 → |
| [sip-negative-control-probes.md](sip-negative-control-probes.md) | SIP | Bots dial a known-bad number (`+18005555111`, a toll-free `555`) as a negative control: a route that `200`s garbage is a honeypot/FAS. We answer it → detectable. Proposes a number-level bogus-reject denylist to pass the test and look like a real PBX (better bait). | Observed | 2026-06-14 → |
| [sip-media-presence-probes.md](sip-media-presence-probes.md) | SIP | Bots stream real RTP audio (a tone) after answer to verify the forward media path carries (FAS/route check) — a probe dimension distinct from answer-supervision and hold. Two styles: ab00day's sustained looped 666 Hz frame (`172.110.223.203`, proven) and a one-shot ~166 Hz burst (`77.42.86.8`, 1 capture). Adds `extras/sip_rtp_triage.py` (RMS + distinct-payload triage). | Observed | 2026-06-16 → |
| [sip-nanp-line-types-whois.md](sip-nanp-line-types-whois.md) | SIP | NANP dial targets are ~83% VoIP (vs ~32% for random numbers — 2.6×, and ~3.9× for wholesale-CLEC VoIP), skewed to DIDs in **rural rate centers** (access-stimulation economics). Bimodal: a few heavily-pumped, sequential-block, rural-wholesale-VoIP numbers carry the monetization signature; a one-off tail (toll-free/round/malformed) is honeypot/dialplan probing. Tooling in `extras/sip-number-exploration/`. | Resolved | 2026-06-16 |
| [sip-intl-clusters-cost.md](sip-intl-clusters-cost.md) | SIP | UK/Israel-Palestine/Italy clusters (~210 numbers, ~314k INVITEs) classified by `phonenumbers` + a Telnyx rate sheet. Cost inverts volume: the money is **Israel/Palestine mobile** ($0.2422/min "Mobile Palestine Region"), not the high-volume UK/IT landlines. Raw INVITEs are mostly **dial-plan recon** (hundreds of prefix-forms per number → ~210 real destinations); the expensive cluster is the most pump-shaped, the cheap fixed blocks are route-discovery anchors. High-value cluster is OVH-hosted, distributed (63 IPs). Lifecycle open. | Resolved | 2026-06-17 |
| [smb-payload-capture.md](smb-payload-capture.md) | SMB | SMB/`SVCCTL` bots staging payloads on the decoy writable share before attempting service creation. | Ongoing | 2026-04 → |
