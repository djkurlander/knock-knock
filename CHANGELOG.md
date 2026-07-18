# Changelog

All notable changes to Knock-Knock, newest first. Dates are UTC.

Pre-3.0 entries are reconstructed from git history and the original GitHub release
notes; from 3.0 onward each release has a hand-written entry here.

## [3.0.0-beta.1] — unreleased (current beta)

The heart of 3.0 is a **protocol extensibility framework**. Adding a honeypot protocol
used to mean hand-editing the monitor, the web app, the database layer, and the dashboard.
Now every protocol is a self-contained module (`protocols/*.py`) that declares everything
about itself — ports, capture, storage, and display — through a single `ProtocolDefinition`,
and the framework wires up the rest (`protocol_api.py`, `protocols/registry.py`,
`EXTENSIBILITY.md`).

### Added

- **Protocol extensibility framework** — the defining feature of 3.0. A declarative
  `ProtocolDefinition` (capture + storage + display) plus a `protocols/` package and
  `protocol_api.py`, so a new protocol is a single self-contained module.
- **All 8 built-in protocols back-ported** onto the framework (SSH, Telnet, FTP, RDP, SMB,
  SIP, HTTP, SMTP) — proof the model carries the originals, not just new work.
- **5 new industrial / IoT / OT protocols** built on the framework — MQTT, Node-RED,
  Modbus, S7, SNMP (8 → 13 protocols). These run on a dedicated node (ash1) to keep the
  flagship dashboard focused on the protocols most visitors recognize; they are a
  proof-of-extensibility, not a main-dashboard centerpiece.
- **Per-protocol display customization** — each protocol declares its own feed columns,
  detail fields, and named display formats (e.g. surfacing user-agent strings; HTTP
  switching between scanner / exploit / probe layouts).
- **Per-knock detail view** — click any live-feed entry to see the full captured record.
- **"Internet Background Radiation"** explainer article/page.

### Changed

- **IP blocklists made prominent.** The public-download blocklist generator has existed
  since v1; 3.0 surfaces it as a first-class threat feed — a dedicated `/blocklist`
  consumer guide (CSF / CrowdSec / ipset / nftables / pfSense recipes), an About-box
  call-to-action, hourly regeneration, 365-day + 30-day feeds, and feed-download analytics
  (logged separately from dashboard viewers).
- **HTTP exploit classifier** expanded (~183 → 238+ named entries), with a regression
  test suite.

### Infrastructure

- Shared per-IP knock throttling across all protocols.
- Unit + integration test suites and CI; Dependabot + pinned dependencies + security
  (CVE) bumps.
- Repository reorganized into a public core (advanced/experimental tooling kept out of
  the public tree).

## [2.0.1] — 2026-05-07

Mostly a bug-fix release — tagging the current best state before checking in the
extensibility rework. Continues 2.0.0's multi-protocol and multi-server aggregation
model with minor cleanup.

## [2.0.0] — 2026-04-26

Consolidated the multi-protocol honeypot with the **multi-server aggregation** model
(feeder nodes forwarding knocks to a central aggregator dashboard), plus dashboard and
protocol-metadata refinements.

## [1.0.x] — early 2026

Initial public releases: a multi-protocol honeypot (SSH, Telnet, FTP, RDP, SMB, SIP,
HTTP, SMTP) with a live WebSocket dashboard (real-time feed, leaderboards, 3D attack
globe), Docker + systemd deployment, timed IP banning, and a public-download IP
blocklist generator.
