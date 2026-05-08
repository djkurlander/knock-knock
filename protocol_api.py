from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
import re


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROTO_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,15}$")
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_FORMAT_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$|^[a-z][a-z0-9_-]{0,31}$")
_DISPLAY_FORMATS = {None, "boolean", "code", "truncate", "list"}
_DISPLAY_SPEC_KEYS = {"label", "value", "value_key", "format"}
_COLUMN_TYPES = {"TEXT", "INTEGER", "REAL", "DATETIME", "BLOB"}
_REPO_DIR = os.path.dirname(os.path.abspath(__file__))


@dataclass(frozen=True)
class Column:
    name: str
    type: str


@dataclass(frozen=True)
class FieldMap:
    source: str
    column: str


@dataclass(frozen=True)
class DisplayField:
    key: str
    label: str
    format: str | None = None


@dataclass(frozen=True)
class PassthroughField:
    key: str
    sanitizer: str = "credential"
    max_len: int | None = None


@dataclass(frozen=True)
class TableDefinition:
    name: str
    columns: list[Column] = field(default_factory=list)


@dataclass(frozen=True)
class ProtocolDefinition:
    name: str
    proto_id: int
    badge: str
    badge_color: str
    ui_order: int
    honeypot_script: str
    default_enabled_entries: list[str] = field(default_factory=list)
    honeypot_args: list[str] = field(default_factory=list)
    honeypot_env: dict[str, str] = field(default_factory=dict)
    option_args: dict[str, list[str]] = field(default_factory=dict)
    option_env: dict[str, dict[str, str]] = field(default_factory=dict)
    supports_user_panel: bool = False
    supports_pass_panel: bool = False
    knock_table: str | None = None
    columns: list[Column] = field(default_factory=list)
    field_map: list[FieldMap] = field(default_factory=list)
    passthrough_fields: list[str | PassthroughField] = field(default_factory=list)
    passthrough_prefixes: list[str] = field(default_factory=list)
    display_fields: list[DisplayField] = field(default_factory=list)
    display_formats: dict[str, list[list[dict]]] = field(default_factory=dict)
    display_format_field: str | None = None
    default_display_format: str | None = None
    extra_tables: list[TableDefinition] = field(default_factory=list)
    process_knock: str | None = None
    after_save: str | None = None


@dataclass(frozen=True)
class ProtocolOverride:
    name: str
    badge: str | None = None
    badge_color: str | None = None
    ui_order: int | None = None
    display_fields: list[DisplayField] | None = None
    display_formats: dict[str, list[list[dict]]] | None = None
    display_format_field: str | None = None
    default_display_format: str | None = None


def _fail(proto: str, msg: str) -> None:
    raise ValueError(f"Invalid protocol definition {proto}: {msg}")


def _check_ident(proto: str, value: str | None, label: str, *, optional: bool = False) -> None:
    if optional and not value:
        return
    if not isinstance(value, str) or not _IDENT_RE.fullmatch(value):
        _fail(proto, f"unsafe {label}: {value!r}")


def _check_display_rows(proto: str, rows, label: str) -> None:
    if not isinstance(rows, list):
        _fail(proto, f"{label} must be a list of rows")
    for row in rows:
        if not isinstance(row, list):
            _fail(proto, f"{label} rows must be lists")
        for spec in row:
            if not isinstance(spec, dict):
                _fail(proto, f"{label} field specs must be objects")
            extra = set(spec) - _DISPLAY_SPEC_KEYS
            if extra:
                _fail(proto, f"{label} field spec has unsupported keys: {sorted(extra)}")
            label_value = spec.get("label")
            if not isinstance(label_value, str) or not label_value.strip():
                _fail(proto, f"{label} field spec requires a non-empty label")
            if "value" not in spec and "value_key" not in spec:
                _fail(proto, f"{label} field spec requires value or value_key")
            if "value_key" in spec:
                _check_ident(proto, spec.get("value_key"), f"{label} value_key")
            if spec.get("format") not in _DISPLAY_FORMATS:
                _fail(proto, f"{label} has unsupported display format: {spec.get('format')!r}")


def validate_protocol_definition(definition: ProtocolDefinition, *, built_in: bool = True) -> None:
    proto = str(getattr(definition, "name", "")).upper()
    if not _PROTO_RE.fullmatch(proto):
        _fail(proto or "<missing>", f"name must be uppercase alnum/underscore, got {definition.name!r}")
    max_id = 999 if built_in else 9999
    min_id = 0 if built_in else 1000
    if not isinstance(definition.proto_id, int) or not (min_id <= definition.proto_id <= max_id):
        _fail(proto, f"proto_id must be in {min_id}-{max_id}, got {definition.proto_id!r}")
    if not isinstance(definition.badge, str) or not (1 <= len(definition.badge) <= 8):
        _fail(proto, f"badge must be 1-8 characters, got {definition.badge!r}")
    if not isinstance(definition.badge_color, str) or not _COLOR_RE.fullmatch(definition.badge_color):
        _fail(proto, f"unsafe badge_color: {definition.badge_color!r}")
    if not isinstance(definition.ui_order, int):
        _fail(proto, f"ui_order must be an integer, got {definition.ui_order!r}")
    if not isinstance(definition.honeypot_script, str) or os.path.isabs(definition.honeypot_script) or ".." in definition.honeypot_script.split(os.sep):
        _fail(proto, f"unsafe honeypot_script: {definition.honeypot_script!r}")
    if not os.path.exists(os.path.join(_REPO_DIR, definition.honeypot_script)):
        _fail(proto, f"honeypot_script does not exist: {definition.honeypot_script!r}")

    for token in set(definition.option_args) | set(definition.option_env):
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            _fail(proto, f"unsafe option token: {token!r}")
    for key, value in definition.honeypot_env.items():
        if not isinstance(key, str) or not _TOKEN_RE.fullmatch(key):
            _fail(proto, f"unsafe honeypot_env key: {key!r}")
        if not isinstance(value, str):
            _fail(proto, f"honeypot_env value must be a string for {key!r}")
    for token, env in definition.option_env.items():
        if not isinstance(env, dict):
            _fail(proto, f"option_env value must be a dict for {token!r}")
        for key, value in env.items():
            if not isinstance(key, str) or not _TOKEN_RE.fullmatch(key):
                _fail(proto, f"unsafe option_env key: {key!r}")
            if not isinstance(value, str):
                _fail(proto, f"option_env value must be a string for {key!r}")

    _check_ident(proto, definition.knock_table, "knock_table", optional=True)
    for column in definition.columns:
        _check_ident(proto, column.name, "column name")
        base_type = str(column.type).split()[0].upper()
        if base_type not in _COLUMN_TYPES:
            _fail(proto, f"unsupported column type for {column.name}: {column.type!r}")
    column_names = {c.name for c in definition.columns}
    for mapping in definition.field_map:
        _check_ident(proto, mapping.source, "field_map source")
        _check_ident(proto, mapping.column, "field_map column")
        if column_names and mapping.column not in column_names:
            _fail(proto, f"field_map target is not declared as a column: {mapping.column!r}")

    for prefix in definition.passthrough_prefixes:
        if not isinstance(prefix, str) or not prefix or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*_?", prefix):
            _fail(proto, f"unsafe passthrough prefix: {prefix!r}")
    for item in definition.passthrough_fields:
        key = item if isinstance(item, str) else item.key
        _check_ident(proto, key, "passthrough field")
        if not isinstance(item, str) and item.sanitizer not in ("credential", "body"):
            _fail(proto, f"unsupported passthrough sanitizer for {item.key}: {item.sanitizer!r}")

    for field in definition.display_fields:
        _check_ident(proto, field.key, "display field key")
        if not isinstance(field.label, str) or not field.label.strip():
            _fail(proto, f"display field label must be non-empty for {field.key!r}")
        if field.format not in _DISPLAY_FORMATS:
            _fail(proto, f"unsupported display field format for {field.key}: {field.format!r}")
    if not isinstance(definition.display_formats, dict):
        _fail(proto, "display_formats must be a dict")
    for name, rows in definition.display_formats.items():
        if not isinstance(name, str) or not _FORMAT_RE.fullmatch(name):
            _fail(proto, f"unsafe display format name: {name!r}")
        _check_display_rows(proto, rows, f"display format {name!r}")
    if definition.display_format_field:
        _check_ident(proto, definition.display_format_field, "display_format_field")
    if definition.default_display_format and definition.default_display_format not in definition.display_formats:
        _fail(proto, f"default_display_format is not declared: {definition.default_display_format!r}")

    for table in definition.extra_tables:
        _check_ident(proto, table.name, "extra table name")
        for column in table.columns:
            _check_ident(proto, column.name, "extra table column name")


def validate_protocol_override(override: ProtocolOverride, existing: ProtocolDefinition) -> None:
    proto = str(getattr(override, 'name', '')).upper()
    if not _PROTO_RE.fullmatch(proto):
        _fail(proto or '<missing>', f"override name must be uppercase alnum/underscore, got {override.name!r}")
    if override.badge is not None:
        if not isinstance(override.badge, str) or not (1 <= len(override.badge) <= 8):
            _fail(proto, f"badge must be 1-8 characters, got {override.badge!r}")
    if override.badge_color is not None:
        if not isinstance(override.badge_color, str) or not _COLOR_RE.fullmatch(override.badge_color):
            _fail(proto, f"unsafe badge_color: {override.badge_color!r}")
    if override.ui_order is not None and not isinstance(override.ui_order, int):
        _fail(proto, f"ui_order must be an integer, got {override.ui_order!r}")
    if override.display_fields is not None:
        if isinstance(override.display_fields, (str, bytes)) or not isinstance(override.display_fields, list):
            _fail(proto, "override display_fields must be a list")
        for f in override.display_fields:
            if not isinstance(f, DisplayField):
                _fail(proto, "override display_fields entries must be DisplayField objects")
            _check_ident(proto, f.key, "display field key")
            if not isinstance(f.label, str) or not f.label.strip():
                _fail(proto, f"display field label must be non-empty for {f.key!r}")
            if f.format not in _DISPLAY_FORMATS:
                _fail(proto, f"unsupported display field format for {f.key}: {f.format!r}")
    if override.display_formats is not None:
        if not isinstance(override.display_formats, dict):
            _fail(proto, "display_formats must be a dict")
        for fmt_name, rows in override.display_formats.items():
            if not isinstance(fmt_name, str) or not _FORMAT_RE.fullmatch(fmt_name):
                _fail(proto, f"unsafe display format name: {fmt_name!r}")
            _check_display_rows(proto, rows, f"display format {fmt_name!r}")
    if override.display_format_field is not None:
        _check_ident(proto, override.display_format_field, "display_format_field")
    if override.default_display_format is not None:
        merged = {**existing.display_formats, **(override.display_formats or {})}
        if override.default_display_format not in merged:
            _fail(proto, f"default_display_format is not declared: {override.default_display_format!r}")


def apply_protocol_override(definition: ProtocolDefinition, override: ProtocolOverride) -> ProtocolDefinition:
    patches = {}
    if override.badge is not None:
        patches['badge'] = override.badge
    if override.badge_color is not None:
        patches['badge_color'] = override.badge_color
    if override.ui_order is not None:
        patches['ui_order'] = override.ui_order
    if override.display_fields is not None:
        patches['display_fields'] = override.display_fields
    if override.display_format_field is not None:
        patches['display_format_field'] = override.display_format_field
    if override.default_display_format is not None:
        patches['default_display_format'] = override.default_display_format
    if override.display_formats is not None:
        patches['display_formats'] = {**definition.display_formats, **override.display_formats}
    return replace(definition, **patches) if patches else definition
