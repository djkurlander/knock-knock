# Changelog

All notable changes to Knock-Knock, newest first. Dates are UTC.

## [3.0.0] — 2026-07-26

The heart of 3.0 is a **protocol extensibility framework**. Adding a honeypot protocol
used to mean hand-editing the monitor, the web app, the database layer, and the dashboard.
Now every protocol is a self-contained module (`protocols/*.py`) that declares everything
about itself — ports, capture, storage, and display — through a single `ProtocolDefinition`,
and the framework wires up the rest (`protocol_api.py`, `protocols/registry.py`,
`docs/HOW_TO_ADD_A_PROTOCOL.md`, `docs/PROTOCOL_ARCHITECTURE.md`).

### Added

- **Protocol extensibility framework** — the defining feature of 3.0. A declarative
  `ProtocolDefinition` (capture + storage + display) plus a `protocols/` package and
  `protocol_api.py`, so a new protocol is a single self-contained module.
- **All 8 built-in protocols back-ported** onto the framework (SSH, Telnet, FTP, RDP, SMB,
  SIP, HTTP, SMTP) — proof the model carries the originals, not just new work.
- **5 new industrial / IoT / OT protocols** built on the framework — MQTT, Node-RED,
  Modbus, S7, SNMP (8 → 13 protocols) — proof the framework reaches well beyond the classic
  login-service honeypots. Enable any of them via `ENABLED_PROTOCOLS`.
- **Per-protocol display customization — user-overridable.** The framework ships sensible
  defaults, but you can **override how any protocol renders** — which feed columns and
  detail fields appear, and which named display format is used (e.g. surface user-agent
  strings, or switch HTTP between scanner / exploit / probe layouts). Works for the
  built-in protocols as well as any you add.
- **One-line Docker setup on Linux — host networking, the new default.** A Docker install
  used to mean editing `docker-compose.override.yml` to publish every honeypot port and keeping
  that list in sync with `ENABLED_PROTOCOLS`, *and* hand-setting `REDACT_SELF_IPS` /
  `DEFAULT_HOSTNAME` so the container could scrub its own identity (bridge NAT hides the host's
  real IP). The new `docker-compose.host.yml` — active by default via a single `COMPOSE_FILE=`
  line in `.env` — removes all of that: honeypots bind host ports directly (**no port list to
  maintain**) and self-redaction **discovers the host's own IP/PTR automatically** (no manual
  `REDACT_SELF_IPS`/`DEFAULT_HOSTNAME`). Setup is one line. It's also the reliable choice for
  **UDP/SIP**, where bridge NAT can mask the real attacker source IP. Bridge networking remains
  the portable fallback for Docker Desktop / macOS / Windows.
- **Per-knock detail view** — right-click (or long-press on touch) any live-feed entry
  to see the full captured record.
- **SMTP body capture, dedup & self-redaction.** SMTP message bodies are captured in full
  (up to 64 KB via `SMTP_MAX_BODY`, previously clipped at 2 KB) and stored **deduplicated**
  in a new `smtp_body_intel` table (one row per distinct body, keyed by SHA-256), linked
  from each knock by `body_id`. Stored bodies are **self-redacted** — the server's own
  IP/host/domain are removed even when hidden inside base64 / quoted-printable / MIME parts
  — and the live feed shows a short **decoded** preview instead of raw encoded text. Built on
  a new declarative `db_only_fields` protocol-API mechanism: a protocol can persist and
  process a field (here the full body) without publishing it to the live feed.
- **Opt-in SMTP header capture for analysis.** `SMTP_SAVE_HEADERS=true` stores self-redacted
  top-level SMTP DATA headers in a DB-only `smtp_header_capture` side table. It is off by
  default and intended as an analysis corpus for future normalized header/campaign intel, not
  as live-feed data.
- **"Internet Background Radiation"** explainer article/page.

### Changed

- **IP blocklists made prominent.** The public-download blocklist generator has existed
  since v1; 3.0 surfaces it as a first-class threat feed — a dedicated `/blocklist`
  consumer guide (CSF / CrowdSec / ipset / nftables / pfSense recipes), an About-box
  call-to-action, hourly regeneration, 365-day + 30-day feeds, and feed-download analytics
  (logged separately from dashboard viewers).
- **HTTP exploit classifier** expanded (~183 → 240+ named entries), with a regression
  test suite.
- **`DEFAULT_HOSTNAME`** — one canonical hostname every protocol advertises, rendered per its
  own convention (SMTP banner as an FQDN, SMB as a short NetBIOS name), and folded into the
  self-redaction identity so it's scrubbed from captured data. Per-protocol overrides
  (`SMTP_HOSTNAME`, `SMB_SERVER_NAME`) plus an `auto` opt-out keep a protocol's built-in
  default when you want it.

### Infrastructure

- The marquee 3.0 change is itself infrastructural: the **protocol extensibility framework**
  (see Added) rewires how every protocol plugs into the monitor, web layer, storage, and
  dashboard — turning protocol support into drop-in modules you can experiment with in
  isolation.
- Shared per-IP knock throttling across all protocols.
- Self-identity redaction extracted to `self_redaction.py`, shared by the monitor and the
  DB backfill so live and historical bodies redact identically.
- SMTP body storage migrates via `updatedb.py` — run once, and it completes the whole migration
  on a single-server honeypot; multi-server aggregators run one extra step
  (`extras/db-migrations/smtp_body_backfill.py` with a fleet identity file; see
  `extras/db-migrations/README.md`).
- Unit + integration test suites and CI; Dependabot + pinned dependencies + security
  (CVE) bumps.
- Docker image hardening: the published image ships `self_redaction.py` and the management
  CLIs, guarded by a CI test that fails the build if the Dockerfile's selective `COPY` ever
  omits a root module the container imports — so a missing module can't ship a crash-looping
  image.

## [2.0.1] — 2026-05-07

Mostly a bug-fix release — tagging the current best state before checking in the
extensibility rework. Continues 2.0.0's multi-protocol and multi-server aggregation
model with minor cleanup.

## [2.0.0] — 2026-04-26

**Went multi-protocol** — added Telnet, FTP, RDP, SMB, SIP, HTTP, and SMTP honeypots
alongside SSH (8 total), and introduced the **multi-server aggregation** model (feeder
nodes forwarding knocks to a central aggregator dashboard). Also added the alternate
compact dashboard (`summary.html`) and protocol-metadata refinements.

## [1.0.x] — early 2026

Initial public releases: an **SSH-only** honeypot with a live WebSocket dashboard
(real-time feed, leaderboards, 3D attack globe), Docker + systemd deployment, timed IP
banning, and a public-download IP blocklist. (Multi-protocol support arrived in 2.0.)
