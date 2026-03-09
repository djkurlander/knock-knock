# Protocol enum — stored as INTEGER in knocks/proto intel tables
PROTO = {'SSH': 0, 'TNET': 1, 'SMTP': 2, 'RDP': 3, 'MAIL': 4, 'FTP': 5, 'SIP': 6}
PROTO_NAME = {v: k for k, v in PROTO.items()}  # reverse lookup: 0->'SSH' etc.

# Declarative protocol metadata for monitor/web UI.
PROTOCOL_META = {
    'SSH': {
        'proto_int': 0,
        'color': '#00ff41',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'ssh_honeypot.py',
    },
    'TNET': {
        'proto_int': 1,
        'color': '#00fbff',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'telnet_honeypot.py',
    },
    'SMTP': {
        'proto_int': 2,
        'color': '#ff00ff',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'smtp_honeypot.py',
    },
    'RDP': {
        'proto_int': 3,
        'color': '#ff1a1a',
        'supports_user_panel': True,
        'supports_pass_panel': False,
        'honeypot_script': 'rdp_honeypot.py',
    },
    'MAIL': {
        'proto_int': 4,
        'color': '#00ffaa',
        'supports_user_panel': False,
        'supports_pass_panel': False,
        'honeypot_script': 'smtp25_honeypot.py',
    },
    'FTP': {
        'proto_int': 5,
        'color': '#c77dff',
        'supports_user_panel': True,
        'supports_pass_panel': True,
        'honeypot_script': 'ftp_honeypot.py',
    },
    'SIP': {
        'proto_int': 6,
        'color': '#ff7a00',
        'supports_user_panel': False,
        'supports_pass_panel': False,
        'honeypot_script': 'sip_honeypot.py',
    },
}

DEFAULT_ENABLED_PROTOCOLS = list(PROTO.keys())
