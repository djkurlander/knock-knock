# Protocol Architecture

This document describes Knock-Knock's current protocol registry and extension
model. For the step-by-step guide to adding a private/local protocol, see
`docs/HOW_TO_ADD_A_PROTOCOL.md`.

The extension system is deliberately small. Protocols describe their stable
facts in Python declarations; `monitor.py` still owns process spawning, knock
sanitization, persistence, intel updates, Redis publishing, websocket delivery,
and rate-limit/block behavior.

## Core Model

Each protocol is represented by a `ProtocolDefinition` from `protocol_api.py`.
Built-in definitions live in `protocols/*.py` and are listed in
`protocols/registry.py`. Local/private definitions can be added in a repo-root
`extensions.py`, which is gitignored.

Protocol definitions declare:

- canonical uppercase protocol name
- stable numeric protocol ID
- badge text, badge color, UI order, and tutorial description
- honeypot script, default enabled entries, and safe option mappings
- user/password panel support
- SQLite knock table and protocol-specific columns
- Redis/websocket passthrough fields and prefixes
- browser display fields and display formats
- optional extra tables
- optional trusted Python hooks

The protocol `name` is the canonical identifier. It is used in
`ENABLED_PROTOCOLS`, `SAVE_KNOCKS`, `MAX_KNOCKS`, Redis keys, SQLite protocol
intel, and frontend filtering. Do not add aliases for the same protocol.

Protocol ID ranges:

- `0-999`: built-in upstream protocols
- `1000-9999`: local/private extensions

Do not reuse an ID after data has been saved with it. Protocol IDs are stored in
SQLite per-protocol intel tables.

## Enabled Protocol Entries

`ENABLED_PROTOCOLS` has three modes:

- unset: use the current default enabled entries from protocol definitions
- empty string: ingest-only mode; spawn no local honeypots
- non-empty string: exact operator-provided spawn list

Entry syntax is:

```text
PROTO[:PORT[:OPTION...]]
```

Examples:

```text
SSH
SMTP:587
MQTT:8883:TLS
```

`PORT`, when present, maps to `--port <port>`. Additional tokens are symbolic
uppercase options declared by the protocol definition. Raw shell fragments are
not allowed.

```python
ProtocolDefinition(
    name="HTTP",
    option_args={
        "TLS": ["--ssl"],
    },
)
```

With that definition, `HTTP:443:TLS` launches the HTTP honeypot with
`--port 443 --ssl`. Unsupported options fail clearly at startup.

## Startup Flow

At startup, the services load protocol metadata once:

1. Load built-in protocol definitions from `protocols/registry.py`.
2. Try to import optional repo-root `extensions.py`.
3. Merge built-ins, local extensions, and local overrides.
4. Validate names, IDs, colors, paths, table names, column names, display
   formats, passthrough fields, and hook paths.
5. Resolve enabled protocol entries and save settings.
6. Create missing SQLite tables and additive protocol columns.
7. Start the requested local honeypot subprocesses.

Adding or changing protocol definitions is a restart-time operation. Restart
both monitor and web services so the merged registry, Redis protocol config,
and browser state agree.

## Knock Flow

During normal operation, `monitor.py` handles each knock through one shared
flow:

```text
read JSON from honeypot
sanitize raw knock
lookup protocol definition
run optional process_knock hook
build common package
copy allowed protocol fields into package
compute intel stats
apply rate limit / block policy
queue SQLite knock/intel write
run optional after_save hook
publish to Redis/websocket
forward to aggregators if configured
```

Unknown protocols are rejected by default. They are not saved, published, or
forwarded. This prevents a bad peer from inventing protocol IDs or causing
inconsistent per-protocol intel.

## Database Model

`monitor.py` owns common schema:

- knock ID and timestamp
- IP/location/ISP/ASN/source columns
- shared intel tables
- source table
- heartbeat table

Protocol definitions own protocol-specific schema:

- per-protocol knock table name
- protocol-specific columns
- optional side tables via `extra_tables`

Only protocol-specific columns are declared in the protocol definition. Common
monitor columns are added by the monitor. Credential columns conventionally use
`username` and `password`; the monitor maps knock fields `user` and `pass` into
those columns automatically.

Same-name fields map automatically:

```python
Column("mqtt_client_id", "TEXT")
```

stores:

```json
{"mqtt_client_id": "client-1"}
```

`FieldMap` still exists for unusual cases, but new protocols should normally
avoid it by emitting protocol fields with the same names as their columns.

Startup schema handling is additive. Missing tables and missing declared
columns can be created automatically. Non-additive changes belong in explicit
migration scripts under `extras/db-migrations/`, run while services are stopped.
Examples include primary-key changes, table reshaping, type changes, column
renames, dropped columns, backfills, and protocol ID remaps.

## Passthrough Model

SQLite persistence and Redis/websocket display are separate surfaces.

Columns decide what is saved in SQLite. Passthrough declarations decide which
protocol-specific fields are sent to the live dashboard and recent Redis lists.

Definitions can allow fields by prefix:

```python
passthrough_prefixes=["mqtt_"]
```

or explicitly:

```python
from protocol_api import PassthroughField

passthrough_fields=[
    PassthroughField("nred_body", sanitizer="body", max_len=10000),
]
```

Only declared protocol fields are copied to Redis/websocket payloads. Common
monitor fields such as `ip`, `proto`, location/ISP data, source data, supported
`user`/`pass`, and display hints are added automatically.

Avoid large passthrough fields unless they are intentionally capped. Redis
payloads are live UI data, not unlimited forensic storage.

## Browser Display

The web app receives protocol metadata from the merged registry. It uses that
metadata for:

- protocol filter buttons and mobile menus
- protocol badge text and color
- user/password panel visibility
- tutorial protocol blocks
- generic feed rendering
- knock details filtering

Simple protocols can use `display_fields`:

```python
display_fields=[
    DisplayField("sip_method", "Method"),
    DisplayField("sip_call_id", "Call ID"),
]
```

Protocols with different layouts by packet type or action should use
`display_formats`:

```python
display_formats={
    "subscribe": [
        [
            {"label": "type", "value_key": "mqtt_packet_type"},
            {"label": "client", "value_key": "mqtt_client_id"},
        ],
        [
            {"label": "topic", "value_key": "mqtt_topic", "format": "truncate", "max_len": 80},
            {"label": "qos", "value_key": "mqtt_qos"},
        ],
    ],
}
```

A knock can select a format with:

```json
{"display_format": "subscribe"}
```

Renderer precedence:

1. Per-knock `display_lines`
2. Per-knock `display_format`
3. Protocol `default_display_format`
4. Protocol `display_fields`
5. Credential fallback

Display specs support:

- `label`
- `label_key`
- `value`
- `value_key`
- `format`
- `max_len`
- `flag_key`

Supported display formats are:

- `boolean`
- `truncate`
- `list`
- `username`
- `password`

The browser escapes labels and values. Protocols must not provide raw HTML or
custom JavaScript.

## Hooks

Hooks are optional trusted local Python functions resolved once at startup.
They are not a plugin sandbox.

```python
ProtocolDefinition(
    name="XTEST",
    process_knock="protocols.xtest:process_knock",
    db_update="protocols.xtest:db_update",
    after_save="protocols.xtest:after_save",
)
```

Available hooks:

- `process_knock(knock, context)`: runs after sanitization and protocol lookup,
  before package construction. Return the knock dict or `None` to drop it.
- `db_update(data, cursor, context)`: runs inside the async DB writer after the
  generic knock/intel updates and before commit. Use this for protocol-owned
  side tables.
- `after_save(knock, package, context)`: runs after the knock is accepted for
  persistence and before Redis/websocket publish. Use this for display/package
  enrichment or best-effort side effects.

Use declarative columns, passthrough fields, and display formats first. Use
hooks only when the protocol needs behavior that declarations cannot express.

## Extra Tables

Protocol-owned side tables should declare their schema with `extra_tables` and
update rows from a `db_update` hook using the provided cursor.

```python
from protocol_api import Column, TableDefinition

extra_tables=[
    TableDefinition(
        name="dial_intel",
        columns=[
            Column("number", "TEXT PRIMARY KEY"),
            Column("hits", "INTEGER"),
            Column("first_seen", "DATETIME"),
            Column("last_seen", "DATETIME"),
        ],
    ),
]
```

Do not open a separate SQLite connection inside a DB hook.

## Local Overrides

`extensions.py` can also define `OVERRIDES`, a list of `ProtocolOverride`
objects that patch display presentation for existing protocols without editing
tracked files.

```python
from protocol_api import ProtocolOverride

EXTENSIONS = []

OVERRIDES = [
    ProtocolOverride(
        name="HTTP",
        display_formats={
            "probe": [[
                {"label": "purpose", "value_key": "http_purpose_label"},
                {"label": "ua", "value_key": "http_user_agent", "format": "truncate"},
            ]],
        },
    ),
]
```

Patchable fields:

- `badge`
- `badge_color`
- `ui_order`
- `display_fields`
- `display_formats`
- `display_format_field`
- `default_display_format`

Structural fields such as `proto_id`, `honeypot_script`, `columns`,
`knock_table`, option mappings, and hooks cannot be overridden.

## Safety Rules

The architecture intentionally avoids dynamic runtime plugins.

The extension system must not:

- execute code received from a honeypot JSON message
- import user-controlled paths
- scan the filesystem per knock
- rebuild the registry per knock
- allow unvalidated SQL identifiers
- allow raw HTML or plugin JavaScript in the browser
- allow shell fragments in `ENABLED_PROTOCOLS`

The extension system should:

- load once at startup
- validate aggressively
- fail fast on invalid definitions
- use dictionary lookups per knock
- keep the monitor as the owner of processing and persistence
- keep the browser as a generic renderer

## Performance

A declarative protocol should cost about the same as a built-in protocol.

Per-knock protocol overhead is limited to:

- one registry lookup
- optional cached hook call
- copying allowed fields
- optional display-format selection
- optional protocol-owned DB side-table update on the existing writer cursor

The expensive work remains GeoIP lookup, Redis writes, SQLite writes, JSON
serialization, and browser rendering.

## Current Built-In Protocols

Built-ins are declared in `protocols/registry.py`. At the time of writing:

- `SSH`
- `TNET`
- `FTP`
- `RDP`
- `HTTP`
- `SMTP`
- `SMB`
- `SIP`
- `MQTT`
- `NRED`
- `MODB`
- `S7`
- `SNMP`

