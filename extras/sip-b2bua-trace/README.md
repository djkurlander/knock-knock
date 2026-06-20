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

# Listener verdict: is the callee/bait audio we relay actually reaching a consumer?
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
- **Listener verdict** (`--listeners`, also a column in `--completions` and a tally
  in the summary): does the audio we relay actually reach a consumer? Fuses three
  per-bridge signals the B2BUA now emits — `stage=sdp_media` (the RTP endpoint the
  bot advertised + a reachability class: `global`/`private`/`unspecified`/…),
  `stage=rtp_unreachable` (our relay drew an ICMP port-unreachable — nobody on that
  port), and inbound RTP/DTMF (positive media). Verdicts:
  - `listener` — engaged: sent us sustained RTP or DTMF (even behind a private SDP,
    the B2BUA latches onto the real RTP source, so our audio is delivered there).
  - `not-listener` — relay bounced off a closed port, or it advertised an unroutable
    endpoint (private/absent/…) and sent nothing to latch onto.
  - `possible` — advertised a real public endpoint, no bounce, but stayed silent:
    could be receiving, unprovable from our side.
  - `unknown` — pre-instrumentation bridge (no `sdp_media` line).

  The per-actor roll-up headlines each `(source IP → destination)` with its dominant
  verdict and keeps the `L/P/N` split, so e.g. the Albania embassy beacon reads
  `not-listener cls=private addr=192.168.1.83:25282` — a fixed RFC1918 media endpoint
  it can't receive on, confirming the call-tree bait is for naught for that actor.

See the investigation notes: [../notes/sip-intl-clusters-cost.md](../notes/sip-intl-clusters-cost.md),
[../notes/sip-ab00day-audio-beacon.md](../notes/sip-ab00day-audio-beacon.md),
[../notes/sip-107189-cli-counter.md](../notes/sip-107189-cli-counter.md),
[../notes/sip-embassy-beacons.md](../notes/sip-embassy-beacons.md).
