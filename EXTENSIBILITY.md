# Protocol Extensibility Plan

## Summary

Add a simple declarative protocol extension model so new protocols can be added without touching many unrelated parts of the app. Built-in protocols and customer-added protocols should share the same internal registry shape.

The goal is not to create a broad dynamic plugin runtime. The goal is to move protocol facts into clear declarations, while keeping `monitor.py` in control of execution flow, sanitization, persistence, Redis publishing, and browser delivery.

## Key Changes

Introduce a protocol definition layer with these concepts:

- `ProtocolDefinition`: one declarative object per protocol.
- `extensions.py`: optional local/customer file that exports `EXTENSIONS = [...]`.
- `protocol_api.py`: dataclasses, validation, registry merge helpers, and safe handler loading.
- Optional protocol hook modules such as `protocols/sip.py` or `protocols/mqtt.py`.
- Existing built-in protocols move toward the same registry model as extensions.

A protocol definition should be able to declare:

- Stable short protocol name, numeric ID, UI order, badge text, and badge color.
- Honeypot script and default ports.
- Whether the protocol supports user and password panels.
- SQLite knock table name, extra columns, and raw JSON field-to-column mapping.
- Sanitized protocol field prefixes or explicit allowed passthrough fields.
- Browser display fields for generic protocol detail rendering.
- Optional processing hooks for special behavior.

Example shape:

```python
ProtocolDefinition(
    name="MQTT",
    proto_id=9,
    badge="MQTT",
    badge_color="teal",
    ui_order=90,
    default_enabled_entries=["MQTT:1883", "MQTT:8883"],
    honeypot_script="honeypots/mqtt_honeypot.py",
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_mqtt",
    columns=[
        Column("username", "TEXT"),
        Column("password", "TEXT"),
        Column("mqtt_port", "INTEGER"),
        Column("mqtt_packet_type", "TEXT"),
        Column("mqtt_client_id", "TEXT"),
        Column("mqtt_topic", "TEXT"),
        Column("mqtt_tls", "INTEGER"),
    ],
    field_map=[
        FieldMap("user", "username"),
        FieldMap("pass", "password"),
        FieldMap("mqtt_port", "mqtt_port"),
        FieldMap("mqtt_packet_type", "mqtt_packet_type"),
        FieldMap("mqtt_client_id", "mqtt_client_id"),
        FieldMap("mqtt_topic", "mqtt_topic"),
        FieldMap("mqtt_tls", "mqtt_tls"),
    ],
    display_fields=[
        DisplayField("mqtt_port", "Port"),
        DisplayField("mqtt_tls", "TLS", format="boolean"),
        DisplayField("mqtt_packet_type", "Packet"),
        DisplayField("mqtt_client_id", "Client ID"),
        DisplayField("mqtt_topic", "Topic"),
    ],
)
```

The `name` is the only canonical protocol identifier. It should be short, uppercase, and stable, and it is the value used in `ENABLED_PROTOCOLS`, `SAVE_KNOCKS`, `MAX_KNOCKS`, Redis keys, SQLite protocol identity, and frontend filtering. Do not support separate long names, short names, or aliases in v1. If a protocol has a longer public name, choose a short canonical key such as `BAC` and use that consistently.

Protocol numeric IDs are split into two ranges:

- `0-999`: reserved for built-in protocols assigned by this upstream repository.
- `1000-9999`: reserved for local/private extensions that are not expected to be persisted to this upstream repository.

The upstream repo must never assign protocol IDs outside `0-999`. Local extension IDs may conflict between independent installs, and that is acceptable because they are local identities. Once a protocol ID is assigned in either range, it should not be reassigned within that repo or install because SQLite intel tables persist protocol IDs. If a local extension is later upstreamed as a built-in protocol, it should receive a new official `0-999` ID; existing private installs that want to preserve old data can handle that with a local migration.

## Enabled Protocol Entries

`ENABLED_PROTOCOLS` should have three distinct meanings:

- Unset: use the current upstream default enabled entry list.
- Empty string: explicit ingest-only mode; spawn no local honeypots.
- Non-empty string: exact operator-provided spawn list.

The upstream default list is not frozen forever. It should represent the current built-in protocol set that the repo wants to run by default. For example, today's default is equivalent to:

```text
SSH,TNET,FTP,RDP,SMB,SIP,SMTP:25,SMTP:587,HTTP:80,HTTP:443
```

When new protocols such as MQTT or NRED become built-ins, the upstream default list may expand.

Entry syntax should be:

```text
ENTRY := PROTO[:PORT[:OPTION...]]
```

`PROTO` is the canonical protocol name. `PORT`, when present, must be an integer. Additional colon-separated values are symbolic uppercase option/profile tokens interpreted by that protocol's definition.

Options should not be passed through as a raw string such as `--extras` or `HONEYPOT_OPTIONS`. Instead, the protocol definition should explicitly map supported option tokens to safe argv/env fragments:

```python
ProtocolDefinition(
    name="HTTP",
    honeypot_script="honeypots/http_honeypot.py",
    option_args={
        "TLS": ["--ssl"],
    },
)
```

With that definition, `HTTP:443:TLS` launches the HTTP honeypot with `--port 443 --ssl`. For another protocol, `MQTT:8883:TLS:OPEN` could map to `--port 8883 --tls` plus a declared environment value such as `MQTT_AUTH_MODE=open`.

Rules:

- `PORT` maps to `--port <port>` by default unless the protocol definition overrides the port argument name.
- Options are protocol-specific; unsupported options should fail clearly at startup.
- Options may map only to declared argv/env fragments.
- Do not allow raw command fragments or shell syntax in `ENABLED_PROTOCOLS`.

This entry shape is intentionally the v1 boundary. Do not add a richer nested spawn-profile format until a real built-in or extension protocol needs behavior that cannot be expressed as `PROTO[:PORT[:OPTION...]]` plus protocol-declared option mappings.

## Monitor Architecture

At startup, `monitor.py` should:

- Load built-in protocol definitions.
- Try to import optional `extensions.py`; if missing, use no extensions.
- Validate and merge built-ins plus extensions into one registry.
- Reject duplicate protocol names, duplicate protocol IDs, invalid badges, invalid colors, unsafe table/column names, and missing honeypot scripts.
- Resolve optional hook strings such as `"protocols.sip:after_save"` once at startup, not per knock.

During knock handling, `monitor.py` should keep one stable flow:

```text
read JSON from honeypot
sanitize raw knock
lookup protocol definition
derive user/pass visibility from protocol definition
build common package
apply optional process_knock hook
copy allowed protocol fields into package
attach optional structured display lines
compute intel stats
apply rate limit / ban policy
save generic knock row
run optional after_save hook after the main DB commit
publish to Redis/websocket
```

Extensions should never send Python code over the wire. Any custom Python routine must be trusted local code installed on the server and referenced by module path.

## Hook Contract

Hooks are optional trusted local Python functions resolved once at startup. They should be synchronous and narrow. They are not a general plugin runtime.

`process_knock` runs after sanitization and protocol lookup, before package construction, intel updates, DB save, and Redis/websocket publish:

```python
def process_knock(knock: dict, context: KnockContext) -> dict | None:
    ...
```

It may normalize fields, add derived fields, classify protocol actions, attach `display_lines`, or return `None` to drop the knock. It may mutate and return the same dict or return a new dict. The monitor uses the returned dict. If it raises an exception, the monitor should log a warning and drop that knock without crashing.

`after_save` runs after the main knock/intel DB transaction commits:

```python
def after_save(knock: dict, package: dict, context: KnockContext) -> None:
    ...
```

It is for best-effort protocol-specific side effects such as SIP-style aggregate side tables. Its return value is ignored. If it raises an exception, the monitor should log a warning, keep the main knock saved, and continue to Redis/websocket publishing.

Hooks should not be used for behavior that must be transactionally inseparable from the main knock save. If a protocol needs transactional persistence, prefer declarative table/field maps in v1 and consider a later explicit transaction-hook feature only if real protocols require it.

## Unknown Protocols and Aggregators

Aggregators and ingest-only monitors may receive forwarded knocks for protocols that are not present in their local merged registry. In v1, unknown protocols should be rejected by default.

If a knock's `proto` is not known locally:

- Drop the knock.
- Log a clear warning with the source, protocol name, and source IP when available.
- Do not save it to SQLite.
- Do not update generic or per-protocol intel tables.
- Do not publish it to Redis/websocket.
- Do not forward it further.
- Rate-limit repeated warnings so a bad peer cannot spam logs.

Do not silently map unknown protocols to an existing protocol ID. In particular, unknown protocols must not fall back to SSH or any other built-in protocol.

Future work may allow display-only handling for unknown protocols if forwarded knocks include safe structured display hints such as `display_lines`. Even then, unknown protocols should not update SQLite protocol intel unless the receiving aggregator has a local protocol definition with a stable protocol ID.

## Passthrough and Sanitization

Protocol definitions should explicitly declare which protocol-specific fields are copied into the Redis/websocket package. These fields are for live dashboard display and recent-feed state; they are separate from SQLite persistence, which is controlled by the protocol's DB field map.

Definitions may declare exact passthrough fields, passthrough prefixes, or both:

```python
ProtocolDefinition(
    name="MQTT",
    passthrough_prefixes=["mqtt_"],
)
```

```python
ProtocolDefinition(
    name="NRED",
    passthrough_fields=[
        "nred_method",
        "nred_path",
        "nred_purpose",
        "nred_exploit",
    ],
)
```

If neither `passthrough_fields` nor `passthrough_prefixes` is declared, only common monitor package fields are sent to Redis/websocket. Protocol-specific fields are not exposed by default.

Passed-through string fields should be sanitized by default. Sanitization means removing or replacing cryptic binary/control-heavy values and redacting this server's own IPs, hostnames, and configured self-identifiers. Empty credential-style values are not converted to `<none>` by monitor sanitization; that is presentation behavior handled by the browser.

Field length limits should be explicit for large body-like fields. The default body-style limit should remain conservative, such as 2000 characters, but a protocol may opt into a larger cap per field:

```python
PassthroughField("nred_body", sanitizer="body", max_len=10000)
```

Avoid unlimited passthrough fields by default. Large values can bloat Redis payloads, websocket messages, browser memory, and SQLite rows. If a protocol needs full forensic payload retention, prefer a deliberate storage path rather than accidental live-feed passthrough.

## Database Model

The current hardcoded `_KNOCK_EXTRA_COLS` and `_PROTO_KEY_MAP` should move into protocol definitions over time.

The generic DB initializer should create:

- The main per-protocol knock table from each enabled/saved protocol definition.
- Shared intel tables as today.
- Optional protocol-declared side tables.

Protocol definitions are the source of truth for creating missing tables for new protocols. Schema setup should happen at monitor startup after the merged registry is loaded and `ENABLED_PROTOCOLS` / `SAVE_KNOCKS` are parsed. The initializer should create missing per-protocol knock tables for protocols that are both enabled and saved. It should create protocol-declared side tables at startup when the owning protocol is enabled and the table is needed for saved knock data or protocol intel. It may also perform simple additive migrations at startup when the mechanism is deterministic and safe, such as `ALTER TABLE ADD COLUMN` for a newly declared missing column.

Do not create or alter tables during per-knock processing. If a known protocol's save table is missing despite startup initialization, log the DB save failure for that knock rather than trying to migrate inline.

Do not turn `monitor.py` into a general migration framework. Non-additive schema changes should be handled out of band with explicit migration scripts, ideally under `extras/db_migration/`, while the monitor is stopped. This includes column renames, type changes, dropped columns, table reshaping, backfills, and protocol ID remaps. Extension authors are responsible for their own private migrations if they change a deployed extension's schema.

SIP-style side tables should split declarative schema from imperative update logic. The side table shape belongs in `extra_tables` so startup can create or validate it. The row update behavior belongs in a narrow `after_save` hook. For example, SIP can declare `dial_intel` as an extra table, save the main event to `knocks_sip`, and use `after_save` to increment dialed phone number intel.

The table declaration should be declarative:

```python
extra_tables=[
    TableDefinition(
        name="dial_intel",
        columns=[
            Column("number", "TEXT PRIMARY KEY"),
            Column("hits", "INTEGER"),
            Column("first_seen", "DATETIME"),
            Column("last_seen", "DATETIME"),
            Column("country", "TEXT"),
            Column("country_name", "TEXT"),
            Column("lat", "REAL"),
            Column("lng", "REAL"),
        ],
    )
]
```

The hook should contain only the behavior that cannot be expressed as a field map, such as incrementing aggregate rows.

## Browser/UI Model

`main.py` should continue sending `protocol_meta` to the browser, but the metadata should come from the merged protocol registry.

The browser should use protocol metadata for:

- Filter buttons and mobile filter menu items.
- Protocol badge label and badge color.
- User/pass/stats panel visibility.
- Generic protocol detail rendering when no per-knock display shape is provided.

Protocol definitions may include display metadata:

```python
display_fields=[
    DisplayField("sip_method", "Method"),
    DisplayField("sip_dial_number", "Dialed"),
    DisplayField("sip_call_id", "Call ID"),
]
```

`index.html` should prefer a generic renderer for these fields for simple protocols. For protocol knocks whose display depends on packet type, stage, action, or other protocol-specific rules, protocol definitions may also declare reusable display formats. A knock can then select one of those formats with a short symbolic name instead of sending the same `display_lines` structure in every Redis/websocket payload.

Example protocol-level display formats:

```python
display_formats={
    "connect": [
        [
            {"label": "action", "value": "connect"},
            {"label": "client", "value_key": "mqtt_client_id"},
        ],
        [
            {"label": "version", "value_key": "mqtt_version"},
            {"label": "auth", "value_key": "mqtt_auth_result"},
        ],
    ],
    "subscribe": [
        [
            {"label": "action", "value": "subscribe"},
            {"label": "client", "value_key": "mqtt_client_id"},
        ],
        [
            {"label": "topic", "value_key": "mqtt_topic", "format": "code"},
            {"label": "qos", "value_key": "mqtt_qos"},
        ],
    ],
}
```

Example knock selecting a reusable format:

```json
{
  "proto": "MQTT",
  "mqtt_stage": "connect",
  "mqtt_client_id": "paho/1AD14D4A91025A4DC0",
  "mqtt_version": "3.1.1",
  "mqtt_auth_result": "accepted",
  "display_format": "connect"
}
```

Prefer symbolic format names such as `"connect"` or `"subscribe"` over numeric IDs. They are easier to inspect in Redis, browser logs, test fixtures, and operator debugging. Compact numeric aliases can be added later only if payload size becomes a demonstrated problem.

For protocols where the display format naturally follows an existing knock field, the definition may declare a format selector field such as `display_format_field="mqtt_stage"`. The monitor can then set or infer `display_format` from that field when the value matches a declared display format. Explicit per-knock `display_format` should take precedence over inferred values.

Protocols may also have only one reusable format. For example, SSH might declare a single `"ssh"` format for username/password-oriented feed display. In that case, the definition may declare a default such as `default_display_format="ssh"` so every knock does not need to repeat `"display_format": "ssh"`. Explicit per-knock `display_format` should still override the default.

For unusual one-off cases, the protocol's trusted Python hook in `monitor.py` may still normalize the Redis/websocket package into per-knock structured `display_lines` before publish.

Example per-knock display shape:

```json
{
  "proto": "MQTT",
  "mqtt_stage": "subscribe",
  "mqtt_client_id": "paho/1AD14D4A91025A4DC0",
  "mqtt_subscriptions": [{"topic": "#", "qos": 0}],
  "display_lines": [
    [
      {"label": "action", "value": "subscribe"},
      {"label": "client", "value_key": "mqtt_client_id"}
    ],
    [
      {"label": "topic", "value": "#"},
      {"label": "qos", "value": "0"}
    ]
  ]
}
```

The browser should render `display_lines` with a small fixed vocabulary:

- `label`: short field label.
- `value`: literal display value.
- `value_key`: key to read from the knock package.
- Optional `format`: known safe formatter such as `boolean`, `code`, `truncate`, or `list`.

The same row-and-field shape is used by per-protocol `display_formats` and per-knock `display_lines`. The browser should resolve display details in this order:

1. Per-knock `display_lines`.
2. Per-knock `display_format` resolved against the current protocol metadata.
3. Protocol `default_display_format` resolved against the current protocol metadata.
4. Protocol `display_fields`.
5. Existing built-in protocol-specific renderers during the migration period.
6. Generic credential fallback.

The browser must escape all labels and values. It should ignore malformed display entries instead of throwing. It should validate that `display_format` is a string, that the format exists for the knock's protocol, that rows are arrays, that field specs are objects, and that field specs use only the allowed keys `label`, `value`, `value_key`, and `format`.

The browser should render only protocols present in its current protocol metadata. If a knock arrives before protocol metadata has loaded, or if the knock's `proto` is absent from the current frontend protocol registry, the browser should ignore that knock client-side. Do not invent fallback colors, labels, panels, or filter entries for unknown protocols. Server-side unknown-protocol rejection remains the primary guardrail; this browser behavior is a second guardrail for startup ordering, stale cached pages, or mismatched services.

This keeps conditional protocol-specific decisions in Python, where the extension already lives, while keeping `index.html` as a stable renderer.

No protocol extension should provide raw HTML for browser rendering. Extensions should provide structured fields, reusable display formats, or per-knock display lines only.

Do not support loadable plugin JavaScript in v1. Existing built-in JavaScript formatters may remain for complex built-in protocols, but extension protocols should use metadata, `display_formats`, and/or `display_lines`.

Adding a protocol or changing protocol metadata is a restart-time operation in v1. It is acceptable to require restarting both monitor and web services so the merged registry, Redis protocol config, and browser initial state agree.

## Built-In Migration Strategy

Do not refactor every existing protocol implementation at once.

Start by moving declarative facts into the registry:

- protocol IDs
- UI order
- colors and badges
- honeypot scripts
- user/pass panel support
- knock table columns
- field maps
- display fields

Leave existing honeypot scripts alone.

Leave existing special-case browser formatters in place initially, especially SMB and richer SIP/HTTP rendering. Simple protocols such as SSH, TNET, FTP, RDP, and much of SMTP can move to metadata-driven rendering. New extension protocols should prefer declarative `display_fields` or reusable `display_formats`; use backend-prepared `display_lines` only for unusual per-knock layouts that cannot be expressed with a reusable format.

Leave existing special-case monitor behavior in place initially, except where it naturally becomes a small hook. SIP phone-number aggregation is the clearest candidate for a future `after_save` hook.

This keeps the first implementation low-risk while eliminating the current "add protocol in many places" problem.

## Safety Rules

The extension system must not:

- execute code received from a honeypot JSON message
- dynamically import arbitrary user-controlled paths
- scan the filesystem on every knock
- validate or rebuild the registry on every knock
- allow raw SQL identifiers without validation
- allow raw HTML into the browser
- load customer JavaScript into the dashboard in v1

The extension system should:

- load once at startup
- validate aggressively
- fail fast on invalid definitions
- use dictionary lookups per knock
- keep `monitor.py` as the owner of the main processing flow
- keep `index.html` as the owner of actual rendering and escaping

## Performance Expectations

A declarative extension should be essentially the same cost as a built-in protocol.

Per knock overhead should be limited to:

- one protocol registry lookup
- optional cached function call
- generic field copy based on the protocol definition
- optional construction of a small `display_lines` array

The expensive work remains GeoIP lookup, Redis writes, SQLite writes, JSON serialization, and browser rendering. The plugin model itself should not be a meaningful performance concern.

`display_lines` will make Redis/websocket payloads slightly larger, but the dashboard only keeps recent feed data in memory. Do not persist `display_lines` into SQLite; store raw protocol facts in the DB and use display hints only for Redis/websocket presentation.

## Test Plan

Add focused tests for:

- Loading built-ins with no `extensions.py`.
- Loading built-ins plus one extension.
- Rejecting duplicate protocol names.
- Rejecting duplicate protocol IDs.
- Rejecting invalid badge length or unsafe color values.
- Rejecting unsafe table/column names.
- Creating protocol knock tables from declarations.
- Mapping protocol JSON fields into the correct SQLite columns.
- Passing protocol metadata through to browser config.
- Generic browser rendering of declared display fields.
- Generic browser rendering of per-knock `display_lines`.
- Browser escaping for `display_lines` labels and values.
- Optional `process_knock` hook execution.
- Optional `after_save` hook execution for SIP-style side tables.
- Ensuring hook imports are resolved once at startup.

Manual acceptance scenarios:

- Existing SSH/TNET/FTP/RDP/SMB/SIP/HTTP/SMTP behavior remains unchanged.
- Disabled protocols do not appear in filter UI.
- A new MQTT definition can be added in `extensions.py` without editing `monitor.py`.
- MQTT knocks can be displayed with badge, color, detail fields, and optional DB columns.
- MQTT hooks can emit different `display_lines` for CONNECT, SUBSCRIBE, PUBLISH, PINGREQ, and AUTH without adding MQTT-specific JavaScript.
- Bad extension definitions fail clearly at startup.

## Assumptions

- Extensions are trusted local server code, not third-party code loaded from network input.
- `extensions.py` is optional and absent in the base install.
- Built-in protocols remain supported without requiring users to understand the extension model.
- Protocol IDs are stable once released because they are stored in SQLite intel tables.
- Protocol `name` is the canonical short identifier; v1 does not support aliases or separate long display labels.
- The first implementation should prioritize declarative metadata and DB/UI wiring over moving all special cases into hooks.
