# Protocol enum — stored as INTEGER in knocks/proto intel tables
import importlib.util
import os

from protocol_api import ProtocolOverride, validate_protocol_definition, validate_protocol_override, apply_protocol_override

_BASE_PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3, 'FTP': 5, 'SIP': 6, 'SMB': 7, 'HTTP': 8}

# Canonical built-in protocol order for UI controls and displays.
_BASE_PROTOCOL_UI_ORDER = ['SSH', 'TNET', 'FTP', 'RDP', 'SMB', 'SIP', 'HTTP', 'SMTP']

# Declarative protocol metadata for monitor/web UI.
_BASE_PROTOCOL_META = {}


_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_builtin_protocols():
    try:
        from protocols.registry import DEFINITIONS
    except ModuleNotFoundError:
        return []
    return [(definition, True) for definition in DEFINITIONS]


def _load_extensions():
    path = os.path.join(_ROOT_DIR, "extensions.py")
    if not os.path.exists(path):
        return [], []
    spec = importlib.util.spec_from_file_location("knock_knock_extensions", path)
    if not spec or not spec.loader:
        raise ValueError(f"Could not load extension protocol file: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    extensions = getattr(module, "EXTENSIONS", None)
    if extensions is None:
        raise ValueError("extensions.py must define EXTENSIONS = [...]")
    if isinstance(extensions, (str, bytes)) or not hasattr(extensions, "__iter__"):
        raise ValueError("extensions.py EXTENSIONS must be an iterable of ProtocolDefinition objects")
    overrides = getattr(module, "OVERRIDES", [])
    if isinstance(overrides, (str, bytes)) or not hasattr(overrides, "__iter__"):
        raise ValueError("extensions.py OVERRIDES must be an iterable of ProtocolOverride objects")
    return [(definition, False) for definition in extensions], list(overrides)


_extension_protocols, _extension_overrides = _load_extensions()
REGISTERED_PROTOCOLS = _load_builtin_protocols() + _extension_protocols
REGISTERED_PROTOCOL_MAP = {}

PROTO = dict(_BASE_PROTO)
PROTOCOL_META = {name: dict(meta) for name, meta in _BASE_PROTOCOL_META.items()}

_ui_order = {name: idx * 10 for idx, name in enumerate(_BASE_PROTOCOL_UI_ORDER, start=1)}
_seen_ids = {proto_id: name for name, proto_id in PROTO.items()}

for definition, built_in in REGISTERED_PROTOCOLS:
    validate_protocol_definition(definition, built_in=built_in)
    name = str(definition.name).upper()
    if name in REGISTERED_PROTOCOL_MAP:
        raise ValueError(f"Duplicate protocol name in registry: {name}")
    # Built-in definitions may migrate an existing legacy protocol into the registry
    # only when they preserve the canonical name and stored proto ID.
    replaces_base = built_in and name in PROTO and PROTO[name] == definition.proto_id
    if name in PROTO and not replaces_base:
        raise ValueError(f"Duplicate protocol name in registry: {name}")
    if definition.proto_id in _seen_ids and not replaces_base:
        raise ValueError(
            f"Duplicate protocol id in registry: {definition.proto_id} "
            f"for {name}; already used by {_seen_ids[definition.proto_id]}"
        )

    REGISTERED_PROTOCOL_MAP[name] = definition
    PROTO[name] = definition.proto_id
    _seen_ids[definition.proto_id] = name
    _ui_order[name] = int(definition.ui_order)
    PROTOCOL_META[name] = {
        'proto_int': definition.proto_id,
        'color': definition.badge_color,
        'badge': definition.badge,
        'supports_user_panel': bool(definition.supports_user_panel),
        'supports_pass_panel': bool(definition.supports_pass_panel),
        'description': definition.description,
        'ports_label': definition.ports_label,
        'honeypot_script': definition.honeypot_script,
        'honeypot_args': list(definition.honeypot_args),
        'definition': definition,
    }

for _override in _extension_overrides:
    if not isinstance(_override, ProtocolOverride):
        raise ValueError("extensions.py OVERRIDES entries must be ProtocolOverride objects")
    _name = str(getattr(_override, 'name', '')).upper()
    if _name not in REGISTERED_PROTOCOL_MAP:
        raise ValueError(f"Override targets unknown or non-registered protocol: {_name!r}")
    _existing = REGISTERED_PROTOCOL_MAP[_name]
    validate_protocol_override(_override, _existing)
    _patched = apply_protocol_override(_existing, _override)
    REGISTERED_PROTOCOL_MAP[_name] = _patched
    if _override.ui_order is not None:
        _ui_order[_name] = _override.ui_order
    _meta = PROTOCOL_META[_name]
    if _override.badge is not None:
        _meta['badge'] = _patched.badge
    if _override.badge_color is not None:
        _meta['color'] = _patched.badge_color
    _meta['definition'] = _patched

PROTO_NAME = {v: k for k, v in PROTO.items()}  # reverse lookup: 0->'SSH' etc.
PROTOCOL_UI_ORDER = sorted(PROTO, key=lambda name: (_ui_order.get(name, 10000), name))

def sort_protocols_for_ui(protocols):
    normalized = [str(p or '').upper() for p in (protocols or [])]
    unique = []
    for name in normalized:
        if name in PROTO and name not in unique:
            unique.append(name)
    preferred = [name for name in PROTOCOL_UI_ORDER if name in unique]
    extras = sorted([name for name in unique if name not in preferred])
    return preferred + extras


# Keep existing default startup behavior for now. New registered protocols are
# available for explicit configuration, but are not spawned by default yet.
DEFAULT_ENABLED_PROTOCOLS = list(_BASE_PROTOCOL_UI_ORDER)
