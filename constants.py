# Protocol enum — stored as INTEGER in knocks/proto intel tables
PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3, 'MAIL': 4, 'FTP': 5, 'SIP': 6, 'SMB': 7}
PROTO_NAME = {v: k for k, v in PROTO.items()}  # reverse lookup: 0->'SSH' etc.

# Canonical protocol order for UI controls and displays.
PROTOCOL_UI_ORDER = ['SSH', 'TNET', 'FTP', 'RDP', 'SMB', 'SIP', 'MAIL', 'SMTP']

SSH_HONEYPOT_SCRIPT = 'honeypots/ssh_honeypot_asyncssh.py'

# Declarative protocol metadata for monitor/web UI.
PROTOCOL_META = {
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
    'MAIL': {
        'proto_int': 4,
        'color': '#00ffaa',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'honeypots/smtp_honeypot.py',
        'honeypot_args': ['--port', '25', '--proto', 'MAIL'],
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

def sort_protocols_for_ui(protocols):
    normalized = [str(p or '').upper() for p in (protocols or [])]
    unique = []
    for name in normalized:
        if name in PROTO and name not in unique:
            unique.append(name)
    preferred = [name for name in PROTOCOL_UI_ORDER if name in unique]
    extras = sorted([name for name in unique if name not in preferred])
    return preferred + extras


DEFAULT_ENABLED_PROTOCOLS = list(PROTOCOL_UI_ORDER)
