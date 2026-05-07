# Extensibility Handoff

This note captures the working context for continuing the protocol extensibility work after commit `2c27eb8` on a less sensitive server.

## Current Baseline

Recent committed work:

- `82ae6db Add MQTT and Node-RED honeypots`
- `2c27eb8 Add protocol extensibility registry`

Local runtime files such as `.env.save`, `mqtt_log_*.txt`, `nred_log_*.txt`, and `http_log_*.txt` were intentionally left uncommitted.

The current goal is to make new protocols easier to add without hardcoding every protocol-specific behavior throughout `monitor.py`, while preserving existing behavior for the legacy built-in protocols.

## Design References

Read these first:

- `EXTENSIBILITY.md`
- `protocol_api.py`
- `protocols/registry.py`
- `protocols/mqtt.py`
- `protocols/nred.py`

`EXTENSIBILITY.md` is the authoritative plan. This file is the short operational handoff.

## Important Decisions

- Upstream/built-in protocol IDs use `0-999`.
- Local/private extension IDs use `1000-9999`; conflicts there are acceptable.
- The upstream repo should never allocate outside `0-999`.
- Once an upstream protocol ID is assigned, do not reuse it.
- New protocol knock tables should use monitor-owned standard columns, including `id INTEGER PRIMARY KEY AUTOINCREMENT` and `timestamp`.
- Protocol definitions declare protocol-specific columns only.
- Additive table/column creation is allowed at monitor startup.
- Non-additive schema changes belong in out-of-band migration scripts, like the existing `extras/db_migration` pattern.
- Unknown protocol IDs/names should be dropped rather than silently mapped to SSH.
- Frontend clients may ignore knocks whose protocol metadata has not arrived yet.
- Adding a new protocol can require restarting both monitor and web services.
- Hooks are trusted local Python, resolved once at startup.

## ENABLED_PROTOCOLS Semantics

The intended grammar is:

```text
ENTRY := PROTO[:PORT[:OPTION...]]
```

Examples:

```text
MQTT:1883
MQTT:8883:TLS
NRED:1880:FAKE_TOKEN
SMTP:587
```

Behavior:

- Unset `ENABLED_PROTOCOLS` preserves the previous default protocol set.
- Empty `ENABLED_PROTOCOLS` means ingest-only; do not spawn honeypots.
- Non-empty `ENABLED_PROTOCOLS` is the exact spawn list.
- Options are symbolic tokens validated against the protocol definition.
- Options map to argv via `option_args` or environment variables via `option_env`.
- Do not pass raw shell fragments or arbitrary option strings through the env var.

MQTT and NRED are registered protocols, but are intentionally not part of the default spawn list yet.

## Implemented So Far

### Protocol Definition API

`protocol_api.py` defines the dataclasses used by registered protocols:

- `ProtocolDefinition`
- `TableDefinition`
- `Column`
- `FieldMap`
- `DisplayField`
- `PassthroughField`

The current definitions are intentionally terse and conservative.

### Protocol Registry

`protocols/registry.py` exports:

```python
DEFINITIONS = [MQTT, NRED]
```

The registry is the official place for declarative protocols that need monitor integration. It does not need to list every legacy protocol immediately.

### Runtime Constants

`constants.py` now loads registered definitions and merges them into:

- `PROTO`
- `PROTO_NAME`
- `PROTOCOL_META`
- `PROTOCOL_UI_ORDER`

It validates duplicate names and IDs lightly. Existing legacy constants are preserved.

### MQTT Definition

`protocols/mqtt.py` registers MQTT as proto ID `9`.

Notable details:

- Script: `honeypots/mqtt_honeypot.py`
- Default entries: `MQTT:1883`, `MQTT:8883:TLS`
- `TLS` maps to `--ssl`
- Auth options map to `MQTT_AUTH_MODE`
- Knock table: `knocks_mqtt`
- Uses `passthrough_prefixes=["mqtt_"]`
- `user` and `pass` map to DB columns `username` and `password`

### Node-RED Definition

`protocols/nred.py` registers Node-RED as proto ID `10`, name `NRED`.

Notable details:

- Script: `honeypots/node_red_honeypot.py`
- Default entry: `NRED:1880`
- `TLS` maps to `--ssl`
- Auth options map to `NRED_AUTH_MODE`
- Knock table: `knocks_nred`
- Uses `passthrough_prefixes=["nred_"]`
- `nred_body` has a body sanitizer and `max_len=2000`
- `user` and `pass` map to DB columns `username` and `password`

## monitor.py Work Completed

The monitor now has registry-aware support for these areas.

### ENABLED_PROTOCOLS Parsing

`ProtocolEntry` represents parsed entries. The parser supports legacy entries and the new `PROTO[:PORT[:OPTION...]]` grammar. Legacy env settings should continue to behave as before.

### Honeypot Spawning

Registered protocol definitions can provide:

- script path
- base args
- option-to-arg mappings
- option-to-env mappings

Ports are applied as `--port`. Legacy spawning remains available for existing protocols.

### DB Schema Creation

At startup, when saving knocks is enabled for a registered protocol, monitor creates the registered knock table and adds missing declared columns.

This should not touch existing legacy tables except through the old code paths already present.

### DB Writes

Registered protocols use definition-backed DB mapping:

- Same-name fields map automatically.
- Explicit `field_map` handles aliases such as `user -> username` and `pass -> password`.
- Existing hardcoded maps remain for legacy protocols.

### Passthrough And Sanitization

Passthrough policies are precomputed once at registry load/import time rather than recomputed per knock.

For registered protocols:

- exact `passthrough_fields` are honored
- `passthrough_prefixes` are honored
- strings are sanitized by default
- per-field body handling and `max_len` are supported

The package creation path receives the already-computed passthrough keys so it does not scan protocol fields twice.

Legacy prefix behavior remains for current protocols until they are migrated.

### Unknown Protocol Rejection

Unknown protocol IDs are dropped before GeoIP, DB writes, intel updates, Redis/websocket publishing, or forwarding. The monitor warns once per unknown protocol per process.

### Hooks

Hook paths from definitions are resolved once at startup.

Expected contract:

```python
process_knock(knock, context) -> dict | None
after_save(knock, package, context) -> None
```

`process_knock` runs after sanitization/protocol lookup and before package creation, DB writes, intel, Redis, websocket, and forwarding. Returning `None` drops the knock.

`after_save` runs after the main DB commit and is best effort. Errors are logged but do not undo the saved knock.

MQTT and NRED currently do not define hooks.

### Frontend Runtime Metadata

`index.html` was minimally updated so server-provided protocol metadata can make registered protocols known to the UI. Generic rendering of `display_fields` and `display_lines` has not been implemented yet.

## Honeypot Work Completed

### MQTT Honeypot

`honeypots/mqtt_honeypot.py` supports MQTT connect/follow-up behavior well enough for test-mode capture.

Useful env vars:

- `MQTT_READ_TIMEOUT`
- `MQTT_FOLLOWUP_PACKETS`
- `MQTT_PINGREQ_LOG_EVERY`
- `MQTT_AUTH_MODE`

It responds to valid PINGREQ packets with PINGRESP and can log the first/every Nth PINGREQ depending on `MQTT_PINGREQ_LOG_EVERY`.

`honeypots/mqtt_signatures.json` classifies known MQTT probes such as Censys, ONYPHE, Paho broad subscriptions, Nmap, wildcard topic subscriptions, anonymous connects, and non-CONNECT protocol probes.

### Node-RED Honeypot

`honeypots/node_red_honeypot.py` captures Node-RED-like HTTP activity and classifies it using `honeypots/node_red_exploits.json`.

Important labels include:

- `Node-RED Shell Download Pipeline`
- `Node-RED Temporary Script Execution`
- `Node-RED Embedded Exec Command`
- `Node-RED HVAC Decoy Flow`
- `Node-RED File Write Flow`
- `Node-RED MQTT Flow Deployment`

`remote_code_execution` is the preferred purpose for actual exec/download pipeline flow deployments. The HVAC replacement/decoy flow is currently labeled as `post_exploit_cleanup`.

## Validation Already Performed

Before committing, these checks passed:

```bash
python -m py_compile monitor.py constants.py protocol_api.py protocols/__init__.py protocols/registry.py protocols/mqtt.py protocols/nred.py honeypots/mqtt_honeypot.py honeypots/node_red_honeypot.py
python -m json.tool honeypots/mqtt_signatures.json
python -m json.tool honeypots/node_red_exploits.json
```

Earlier ad hoc tests also verified:

- MQTT and NRED are present in protocol metadata.
- Legacy defaults remain unchanged.
- `MQTT:8883:TLS` maps to `--port 8883 --ssl`.
- `MQTT:1883:REQUIRE` maps to `MQTT_AUTH_MODE=require`.
- `NRED:1880:FAKE_TOKEN` maps to `NRED_AUTH_MODE=fake_token`.
- Registered MQTT/NRED DB table creation and row insertion work in a temp DB.
- Registered passthrough avoids the previous double-scan package path.

## What Is Not Done Yet

High priority:

- End-to-end smoke test on a less sensitive server.
- Verify monitor-spawned MQTT/NRED processes on test ports.
- Verify `SAVE_KNOCKS` creates and writes `knocks_mqtt` and `knocks_nred`.
- Verify Redis/websocket package output contains useful MQTT/NRED fields.
- Verify no legacy behavior regressed when MQTT/NRED are not enabled.

Later:

- Generic frontend rendering for `display_fields` and `display_lines`.
- Better frontend details/context modal for inspecting full knock details.
- Migrate legacy protocols into registry definitions if that proves worth the complexity.
- More protocol-specific hooks if real MQTT/NRED needs emerge.
- More formal tests around parsing, DB mapping, sanitization, and hooks.

## Suggested First Prompt On New Server

After cloning and starting Codex on the less sensitive server, use:

```text
Read EXTENSIBILITY.md and docs/HANDOFF_EXTENSIBILITY.md. We are continuing the protocol extensibility work from commit 2c27eb8. First summarize what is already implemented, what remains, and propose the safest smoke-test plan for this less sensitive server. Do not start or stop any services until I approve the plan.
```

## Suggested Smoke-Test Direction

Use alternate ports first, especially if the server has anything valuable already exposed.

Example direction, to be adapted after reading the local `.env` and service setup:

```bash
ENABLED_PROTOCOLS="MQTT:11883,MQTT:18883:TLS,NRED:11880" \
SAVE_KNOCKS="MQTT,NRED" \
python -u monitor.py
```

Then generate local test knocks against those alternate ports and inspect:

- monitor stdout
- Redis/websocket behavior if enabled
- SQLite tables `knocks_mqtt` and `knocks_nred`
- `user_intel_proto` rows for proto IDs `9` and `10`

Do not perform the first end-to-end test on `la5`; that server has long-running legacy honeypot behavior feeding the aggregator.

## Operational Caution

The old la5 setup has useful continuity in its logs and aggregator feed. Avoid stopping or replacing those long-running services just to test extensibility. The next risky step is monitor-managed spawning of MQTT/NRED, so it belongs on a less sensitive host or on clearly alternate ports.

