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

## Add `extensions.py`

Create a repo-root `extensions.py`. This file is intentionally not present in
the base install.

```python
from protocol_api import Column, DisplayField, FieldMap, ProtocolDefinition


EXTENSIONS = [
    ProtocolDefinition(
        name="XTEST",
        proto_id=1000,
        badge="XT",
        badge_color="#7cc7ff",
        ui_order=1000,
        honeypot_script="honeypots/xtest_honeypot.py",
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
        field_map=[
            FieldMap("user", "username"),
            FieldMap("pass", "password"),
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

Use `field_map` for aliases such as `user -> username` and `pass -> password`.

Schema creation is additive at monitor startup. Missing declared tables and
columns are created. Renames, type changes, drops, and backfills should be done
with an explicit migration while the monitor is stopped.

## Browser Display

For simple protocols, use `display_fields`. For repeated structured layouts,
use `display_formats` and have the honeypot set `display_format` in each knock.

The browser supports field specs with:

- `label`
- `value`
- `value_key`
- `format`

Supported formats:

- `boolean`
- `code`
- `truncate`
- `list`

Do not send HTML. Labels and values are escaped by the browser.

Renderer precedence is:

1. Per-knock `display_lines`.
2. Per-knock `display_format`.
3. Protocol `default_display_format`.
4. Protocol `display_fields`.
5. Built-in legacy renderer.
6. Credential fallback.

Use `display_lines` only when a knock needs a one-off layout that cannot be
represented by a reusable `display_format`.

## Passthrough

Only declared protocol fields are copied to Redis/websocket payloads. Use
prefixes for normal protocol telemetry:

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
- `default_display_format` does not reference a declared format.
- Unsupported passthrough sanitizer.

Fix validation errors before starting monitor/web in production mode.

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
