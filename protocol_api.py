from __future__ import annotations

from dataclasses import dataclass, field


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
    extra_tables: list[TableDefinition] = field(default_factory=list)
    process_knock: str | None = None
    after_save: str | None = None
