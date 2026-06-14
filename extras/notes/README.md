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
| [sip-107189-cli-counter.md](sip-107189-cli-counter.md) | SIP | `107.189.20.125` dials one fixed French mobile (`+33756758573`) with a monotonic ~8.4k/sec counter in the caller ID, and is the **first bot observed to complete (ACK) + silently hold** a call — likely route verification (two depths) against an own beacon, not monetization. | Open | 2026-06-14 → |
| [sip-embassy-beacons.md](sip-embassy-beacons.md) | SIP | Multiple independent toolkits dial four DC foreign-embassy numbers (Albania/France/Saudi/Britain) as 24/7 "always-answers" route-reachability beacons — answer-supervision, then abandon. Dominant actor: ReliableSite ASN 23470 hitting 3 of 4 from shared IPs. The honeypot never calls the embassy; a real vulnerable route would (modulo FAS). | Ongoing | 2026-06-14 → |
| [smb-payload-capture.md](smb-payload-capture.md) | SMB | SMB/`SVCCTL` bots staging payloads on the decoy writable share before attempting service creation. | Ongoing | 2026-04 → |
