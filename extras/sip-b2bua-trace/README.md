# SIP B2BUA trace analysis

Analyze the honeypot B2BUA's call-lifecycle traces — completions, holds, the
silent-vs-media split, and SIP-INFO/DTMF captures.

## Data source

The B2BUA (`honeypots/sip_b2bua.py`) emits `SIPTRACE component=b2bua …` lines for
every bridge stage. With `PBX_TRACE_FILE` set, each line is also appended — with
an ISO-8601 UTC timestamp — to a durable file (default `data/b2bua_trace.log`),
straight from the source.

**Query that file, not the journal.** The systemd journal is a size-capped ring
buffer, and it only carries B2BUA traces from when the prefix became `SIPTRACE`
(Jun 14 2026) — earlier `SIPB2BUA`-prefixed lines never matched monitor's
`*TRACE` passthrough and were dropped. The file is the system-of-record:
complete from the tee's start, durable, self-dating, and far faster to scan than
`journalctl` over a ~half-GB journal.

## Usage

```bash
source .venv/bin/activate

# Summary: outcome breakdown + completed/held destinations (with media-sent)
python extras/sip-b2bua-trace/b2bua_trace.py

# Per-bridge detail for bridges that ACKed / held to cap / BYE'd
python extras/sip-b2bua-trace/b2bua_trace.py --completions --top 20
python extras/sip-b2bua-trace/b2bua_trace.py --completions --number 541139876436

# SIP-INFO / DTMF captures (stage=attacker_info) — IVR keypresses
python extras/sip-b2bua-trace/b2bua_trace.py --dtmf

# Two-axis media analysis: could our callee audio reach them (recv) × did they stream to us (sent)?
python extras/sip-b2bua-trace/b2bua_trace.py --listeners
python extras/sip-b2bua-trace/b2bua_trace.py --listeners --number 12022234942

# Filter, or read a different file / stdin
python extras/sip-b2bua-trace/b2bua_trace.py --ip 172.110.223.197
cat data/b2bua_trace.log | python extras/sip-b2bua-trace/b2bua_trace.py -
```

## What it computes

- **Outcome per bridge** (reconstructed by `id`): `no_ack` (answer-supervision,
  abandoned), `held_to_cap` (held to the call-timeout — monetization-shaped),
  `ack_then_bye` (completed and cleanly released), `bye_no_ack` (media-probe
  style, e.g. ab00day), `cancel`, plus `setup_failed` (no bridge — e.g. RTP pool
  exhaustion).
- **media-sent**: cross-references each bridge's `rtp_dump_armed` filename against
  the RTP dump dir (`--media-dir`, default `data/rtp_dumps`). A present, non-empty
  dump = the attacker actually streamed inbound RTP (tone/audio/RFC2833-DTMF);
  absent = silent (listened only, or held the line without sending). DTMF sent as
  SIP INFO is signaling, not RTP — caught separately as `--dtmf` / `attacker_info`.
- **Concentration** of completed/held bridges by destination, to separate the
  monetization targets (hold-to-cap) from probes.
- **Two-axis media analysis** (`--listeners`, also columns in `--completions` and a
  tally in the summary): "did they listen to the callee audio?" is a *downlink*
  question, so it's tracked separately from *uplink* activity — never collapsed into one
  label (which would hide a bot that's reachable AND engaged, the strongest candidate).
  Two independent axes per bridge, from the signals the B2BUA emits (`stage=sdp_media`
  = advertised RTP endpoint + reachability class; `stage=rtp_unreachable` = our relay
  drew an ICMP port-unreachable; inbound RTP/DTMF = uplink media):
  - **`recv`** (downlink — *the 'listened' axis*): could our callee audio reach them?
    - `reachable` — `cls=global` and no `rtp_unreachable` bounce → it could land.
    - `unreachable` — bounced, or advertised a private/unroutable addr.
    - `unknown` — no `sdp_media` (pre-instrumentation bridge); **not evaluated**, not negative.
  - **`sent`** (uplink): did they stream RTP/DTMF to us? `engaged` / `silent`. Proves an
    active media stack, but says nothing about whether they received our downlink.

  "May have listened" = **`recv=reachable`** (any `sent`); the strongest case is
  **`reachable` AND `engaged`**, which the summary/roll-up count explicitly. The per-actor
  roll-up shows both axes (`recv reach/unr/?`, `sent eng/sil`, `both`) and the reachable
  media address, sorted reachable-first. E.g. the Albania embassy reads
  `recv reach=0/unr=767 sent eng=2/sil=766` — a fixed RFC1918 endpoint it can't receive
  on, confirming the call-tree bait is for naught for that actor.

See the investigation notes: [../notes/sip-intl-clusters-cost.md](../notes/sip-intl-clusters-cost.md),
[../notes/sip-ab00day-audio-beacon.md](../notes/sip-ab00day-audio-beacon.md),
[../notes/sip-107189-cli-counter.md](../notes/sip-107189-cli-counter.md),
[../notes/sip-embassy-beacons.md](../notes/sip-embassy-beacons.md).
