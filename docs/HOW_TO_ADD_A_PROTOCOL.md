# How To Add A Protocol

This guide covers the low-rewiring path for adding a local/private protocol to
Knock-Knock. Use `extensions.py` for local deployments. Use
`protocols/registry.py` only when adding a protocol to the upstream repo.

## Choose An ID

- Built-in upstream protocols use IDs `0-999`.
- Local/private extensions use IDs `1000-9999`.
- Do not reuse an ID after data has been saved with it. Protocol IDs are stored
  in SQLite intel tables.

## Create A Honeypot

A honeypot should write one JSON object per line to stdout for each knock:

```json
{
  "type": "KNOCK",
  "proto": "XTEST",
  "ip": "203.0.113.10",
  "xtest_port": 12345,
  "xtest_action": "probe",
  "xtest_detail": "hello",
  "display_format": "probe"
}
```

Required fields:

- `type`: must be `"KNOCK"`.
- `proto`: canonical uppercase protocol name.
- `ip`: source IP.

Use `user` and `pass` if the protocol captures credentials. Use
protocol-prefixed fields such as `xtest_action` for protocol details.

Some built-in honeypots can be reused by a local extension. MQTT and Node-RED
default to emitting `MQTT` and `NRED`, but accept `KNOCK_PROTO` to override the
emitted protocol name:

```bash
KNOCK_PROTO=XTEST python honeypots/mqtt_honeypot.py --port 12345
```

When launching through the monitor, pass that environment value from the
protocol definition with `honeypot_env`.

## Add `extensions.py`

Create a repo-root `extensions.py`. This file is intentionally not present in
the base install.

```python
from protocol_api import Column, DisplayField, ProtocolDefinition


EXTENSIONS = [
    ProtocolDefinition(
        name="XTEST",
        proto_id=1000,
        badge="XT",
        badge_color="#7cc7ff",
        ui_order=1000,
        honeypot_script="honeypots/xtest_honeypot.py",
        honeypot_env={
            "KNOCK_PROTO": "XTEST",
        },
        default_enabled_entries=["XTEST:12345"],
        supports_user_panel=True,
        supports_pass_panel=True,
        knock_table="knocks_xtest",
        columns=[
            Column("username", "TEXT"),
            Column("password", "TEXT"),
            Column("xtest_port", "INTEGER"),
            Column("xtest_action", "TEXT"),
            Column("xtest_detail", "TEXT"),
        ],
        passthrough_prefixes=["xtest_"],
        display_fields=[
            DisplayField("xtest_action", "Action"),
            DisplayField("xtest_detail", "Detail"),
        ],
        display_formats={
            "probe": [
                [
                    {"label": "action", "value_key": "xtest_action"},
                    {"label": "detail", "value_key": "xtest_detail", "format": "truncate"},
                ],
            ],
        },
        default_display_format="probe",
    ),
]
```

Restart both monitor and web after changing protocol definitions.

## Enable The Protocol

For a local smoke test:

```bash
ENABLED_PROTOCOLS=XTEST:12345 python monitor.py --save-knocks ALL
```

Entry syntax is:

```text
PROTO[:PORT[:OPTION...]]
```

Options must be declared by the protocol definition:

```python
option_args={
    "TLS": ["--ssl"],
}
option_env={
    "REQUIRE": {"XTEST_AUTH_MODE": "require"},
}
```

Then this is valid:

```bash
ENABLED_PROTOCOLS=XTEST:12345:TLS:REQUIRE python monitor.py --save-knocks ALL
```

Raw shell fragments are not allowed in `ENABLED_PROTOCOLS`.

## Database Mapping

The monitor owns common columns such as ID, timestamp, IP, country, ISP, ASN,
and source. A protocol definition declares only protocol-specific columns.

Same-name fields map automatically:

```python
Column("xtest_action", "TEXT")
```

maps from:

```json
{"xtest_action": "probe"}
```

Credential fields have one conventional alias: `Column("username", "TEXT")`
stores the knock's `user` field, and `Column("password", "TEXT")` stores the
knock's `pass` field. Other protocol columns should normally use the same name
as the emitted knock field.

Schema creation is additive at monitor startup. Missing declared tables and
columns are created. Renames, type changes, drops, and backfills should be done
with an explicit migration while the monitor is stopped.

## Hooks And Side Tables

Most protocols should not need hooks. Use declarative columns, passthrough
fields, and display formats first.

When a protocol needs trusted Python behavior, declare a module function by
path:

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

Declare side-table schemas with `extra_tables` so startup creates them:

```python
from protocol_api import Column, TableDefinition

extra_tables=[
    TableDefinition(
        name="xtest_intel",
        columns=[
            Column("key", "TEXT PRIMARY KEY"),
            Column("hits", "INTEGER"),
            Column("last_seen", "DATETIME"),
        ],
    ),
]
```

Then update that table from `db_update` using the provided cursor. Do not open a
separate SQLite connection from a DB hook.

## Browser Display

For simple protocols, use `display_fields`. For repeated structured layouts,
use `display_formats` and have the honeypot set `display_format` in each knock.

The browser supports field specs with:

- `label`
- `value`
- `value_key`
- `format`
- `max_len`
- `flag_key`

Supported formats:

- `boolean`
- `truncate`
- `list`
- `username`
- `password`

Use `max_len` to cap long text fields without creating a new format:

```python
{"label": "detail", "value_key": "xtest_detail", "format": "truncate", "max_len": 60}
```

Use `flag_key` when the value should display with a country flag:

```python
{"label": "country", "value_key": "xtest_country_name", "flag_key": "xtest_country"}
```

Do not send HTML. Labels and values are escaped by the browser.

Renderer precedence is:

1. Per-knock `display_lines`.
2. Per-knock `display_format`.
3. Protocol `default_display_format`.
4. Protocol `display_fields`.
5. Credential fallback.

Use `display_lines` only when a knock needs a one-off layout that cannot be
represented by a reusable `display_format`.

## Passthrough

Only declared protocol fields are copied to Redis/websocket payloads; common
monitor fields such as `ip`, `proto`, location/ISP data, source data, supported
`user`/`pass`, and display hints are added automatically. Use prefixes for
normal protocol telemetry:

```python
passthrough_prefixes=["xtest_"]
```

Use explicit fields for special handling:

```python
from protocol_api import PassthroughField

passthrough_fields=[
    PassthroughField("xtest_body", sanitizer="body", max_len=2000),
]
```

Avoid large live-feed fields unless they are intentionally capped.

## Validation

Protocol definitions are validated at startup. Common failures:

- Extension ID is not in `1000-9999`.
- Duplicate protocol name or ID.
- Unsafe table, column, field, or format names.
- Missing honeypot script.
- Unsupported display spec key.
- Unsupported display format.
- Invalid `max_len`.
- `default_display_format` does not reference a declared format.
- Unsupported passthrough sanitizer.

Fix validation errors before starting monitor/web in production mode.

## Customizing an Existing Protocol

To change the display presentation of an existing registered protocol without
editing tracked files, use `OVERRIDES` in `extensions.py`. Because
`extensions.py` is gitignored, customizations survive `git pull` without
conflicts.

```python
from protocol_api import ProtocolOverride

EXTENSIONS = []

OVERRIDES = [
    ProtocolOverride(
        name="HTTP",
        display_formats={
            "probe": [[
                {"label": "purpose", "value_key": "http_purpose"},
                {"label": "UA",      "value_key": "http_user_agent", "format": "truncate"},
            ]],
        },
    ),
]
```

`display_formats` is merged — only the format names you list are added or
replaced; all other existing formats are kept. The patchable fields are:

- `badge` and `badge_color` — rename or recolor the protocol badge
- `ui_order` — reposition the protocol in the UI
- `display_fields` — replace the full display field list
- `display_formats` — merge additional or replacement named formats
- `display_format_field` and `default_display_format` — change format selection

Structural fields (`proto_id`, `honeypot_script`, `columns`, `knock_table`,
etc.) cannot be overridden. Overrides only work on protocols in the registry
(`protocols/registry.py` or your own `EXTENSIONS`).

Restart both monitor and web after changing `extensions.py`.

## Smoke Test Checklist

Use an isolated DB and Redis DB first:

```bash
mkdir -p /tmp/kk-xtest-smoke
DB_DIR=/tmp/kk-xtest-smoke REDIS_DB=15 \
  ENABLED_PROTOCOLS=XTEST:12345 \
  python monitor.py --save-knocks ALL
```

In another terminal, trigger the honeypot. Then inspect:

```bash
redis-cli -n 15 get knock:config:enabled_protocols
redis-cli -n 15 get knock:config:protocol_meta
redis-cli -n 15 lrange knock:recent 0 3
sqlite3 /tmp/kk-xtest-smoke/knock_knock.db ".tables"
```

Expected results:

- Protocol appears in enabled protocols.
- Protocol metadata includes color, badge, display fields/formats.
- Recent Redis payload includes protocol fields and optional `display_format`.
- SQLite contains the declared knock table if `--save-knocks` includes it.

After backend smoke passes, start the web service and verify the dashboard shows
the protocol filter, badge, feed row, and display details.
