# Local Protocol Overrides

Knock-Knock supports site-specific customization of built-in protocol definitions without modifying the core codebase.

## How it works

On startup, `constants.py` looks for an `extensions.py` file in the project root. If found, it loads two lists from it:

- **`EXTENSIONS`** — `ProtocolDefinition` objects for entirely new honeypot protocols
- **`OVERRIDES`** — `ProtocolOverride` objects that patch fields on built-in protocols

`extensions.py` is gitignored, so your customizations stay local and are never pushed upstream.

## Getting started

Copy the example file to the project root and edit it:

```bash
cp extras/overrides/extensions.py.example extensions.py
```

Then restart the services to apply your changes:

```bash
./restart.sh
```

## What can be overridden

`ProtocolOverride` supports these fields:

| Field | Description |
|---|---|
| `badge` | Short badge label shown in the UI (1–8 chars) |
| `badge_color` | Hex color for the badge |
| `ui_order` | Position in the protocol switcher |
| `display_fields` | Fallback fields shown when no display format matches |
| `display_formats` | Per-format display row definitions (merged, not replaced) |
| `display_format_field` | Knock field used to select the display format |
| `default_display_format` | Format used when no match is found |

### display_formats merging

Override `display_formats` are merged at the format-key level. Only the format keys you specify are replaced — unspecified formats inherit from the base definition unchanged. This means future additions to the base definition flow through automatically.

### Display spec fields

Each row in a display format is a list of field specs:

| Key | Description |
|---|---|
| `label` | Hardcoded label string |
| `label_key` | Field name whose value is used as the label (dynamic) |
| `value` | Hardcoded value (always shown) |
| `value_key` | Field name whose value is shown (suppressed when null/empty) |
| `format` | One of: `truncate`, `boolean`, `list`, `username`, `password` |
| `max_len` | Truncation limit in characters (1–500, default 140) |
| `flag_key` | Field name whose ISO code is rendered as a country flag |

Rows where all values are null or empty are suppressed automatically — no special handling needed.
