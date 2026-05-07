# Protocol enum — stored as INTEGER in knocks/proto intel tables
import importlib.util
import os

from protocol_api import validate_protocol_definition

_BASE_PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3, 'FTP': 5, 'SIP': 6, 'SMB': 7, 'HTTP': 8}

# Canonical built-in protocol order for UI controls and displays.
_BASE_PROTOCOL_UI_ORDER = ['SSH', 'TNET', 'FTP', 'RDP', 'SMB', 'SIP', 'HTTP', 'SMTP']

SSH_HONEYPOT_SCRIPT = 'honeypots/ssh_honeypot_asyncssh.py'

# Declarative protocol metadata for monitor/web UI.
_BASE_PROTOCOL_META = {
    'SSH': {
        'proto_int': 0,
        'color': '#00ff41',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': SSH_HONEYPOT_SCRIPT,
    },
    'TNET': {
        'proto_int': 1,
        'color': '#00fbff',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'honeypots/telnet_honeypot.py',
    },
    'SMTP': {
        'proto_int': 2,
        'color': '#ff00ff',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'honeypots/smtp_honeypot.py',
    },
    'RDP': {
        'proto_int': 3,
        'color': '#ff1a1a',
        'supports_user_panel': True,
        'supports_pass_panel': False,
        'honeypot_script': 'honeypots/rdp_honeypot.py',
    },
    'HTTP': {
        'proto_int': 8,
        'color': '#00ffaa',
        'supports_user_panel': False,
        'supports_pass_panel': False,
        'honeypot_script': 'honeypots/http_honeypot.py',
        'honeypot_args': [],
    },
    'FTP': {
        'proto_int': 5,
        'color': '#FFFF77',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'honeypots/ftp_honeypot.py',
    },
    'SIP': {
        'proto_int': 6,
        'color': '#ff7a00',
        'supports_user_panel': False,
        'supports_pass_panel': False,
        'honeypot_script': 'honeypots/sip_honeypot.py',
    },
    'SMB': {
        'proto_int': 7,
        'color': '#d6d9df',
        'supports_user_panel': True,
        'supports_pass_panel': False,
        'honeypot_script': 'honeypots/smb_honeypot.py',
    },
}


_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_builtin_protocols():
    try:
        from protocols.registry import DEFINITIONS
    except ModuleNotFoundError:
        return []
    return [(definition, True) for definition in DEFINITIONS]


def _load_extension_protocols():
    path = os.path.join(_ROOT_DIR, "extensions.py")
    if not os.path.exists(path):
        return []
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
    return [(definition, False) for definition in extensions]


REGISTERED_PROTOCOLS = _load_builtin_protocols() + _load_extension_protocols()
REGISTERED_PROTOCOL_MAP = {}

PROTO = dict(_BASE_PROTO)
PROTOCOL_META = {name: dict(meta) for name, meta in _BASE_PROTOCOL_META.items()}

_ui_order = {name: idx * 10 for idx, name in enumerate(_BASE_PROTOCOL_UI_ORDER, start=1)}
_seen_ids = {proto_id: name for name, proto_id in PROTO.items()}

for definition, built_in in REGISTERED_PROTOCOLS:
    validate_protocol_definition(definition, built_in=built_in)
    name = str(definition.name).upper()
    if name in PROTO or name in REGISTERED_PROTOCOL_MAP:
        raise ValueError(f"Duplicate protocol name in registry: {name}")
    if definition.proto_id in _seen_ids:
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
        'honeypot_script': definition.honeypot_script,
        'honeypot_args': list(definition.honeypot_args),
        'definition': definition,
    }

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
