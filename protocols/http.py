from protocol_api import Column, ProtocolDefinition


_PURPOSE_LABELS = {
    'rce':                 'remote code execution',
    'credential_theft':    'credential theft',
    'device_infiltration': 'device infiltration',
    'config_exposure':     'data exfiltration',
    'path_traversal':      'path traversal',
    'proxy_abuse':         'proxy abuse',
    'malware_comm':        'malware communication',
    'crypto_mining':       'cryptocurrency mining',
    'open_redirect':       'open redirect probe',
    'app_discovery':       'application discovery',
    'api_probe':           'API probe',
    'research_scanner':    'research scanner',
    'protocol_probe':      'protocol probe',
    'mass_scanner':        'mass scanner',
    'unknown':             'unknown',
}

def after_save(knock, package, _ctx):
    raw_purpose = knock.get('http_purpose')
    if raw_purpose:
        package['http_purpose_label'] = _PURPOSE_LABELS.get(raw_purpose, raw_purpose.replace('_', ' '))

    has_exploit = bool(knock.get('http_exploit'))
    is_scanner  = raw_purpose == 'research_scanner'

    if has_exploit and is_scanner:
        fmt = 'scanner'
    elif has_exploit:
        fmt = 'exploit'
    else:
        fmt = 'probe'

    package['display_format'] = fmt


DEFINITION = ProtocolDefinition(
    name="HTTP",
    proto_id=8,
    badge="HTTP",
    badge_color="#00ffaa",
    ui_order=70,
    honeypot_script="honeypots/http_honeypot.py",
    honeypot_args=[],
    description="HTTP is the web protocol, and bots probe it for exploitable apps and known vulnerabilities.",
    default_enabled_entries=["HTTP:80", "HTTP:443"],
    supports_user_panel=False,
    supports_pass_panel=False,
    knock_table="knocks_http",
    columns=[
        Column("http_port",       "INTEGER"),
        Column("http_method",     "TEXT"),
        Column("http_path",       "TEXT"),
        Column("http_purpose",    "TEXT"),
        Column("http_exploit",    "TEXT"),
        Column("http_host",       "TEXT"),
        Column("http_user_agent", "TEXT"),
        Column("http_body",       "TEXT"),
    ],
    passthrough_prefixes=["http_"],
    after_save="protocols.http:after_save",
    display_formats={
        "probe": [
            [{"label": "purpose", "value_key": "http_purpose_label"}],
            [{"label": "method",  "value_key": "http_method"},
             {"label": "path",    "value_key": "http_path",   "format": "truncate"}],
            [{"label": "body",    "value_key": "http_body",   "format": "truncate", "max_len": 40}],
        ],
        "exploit": [
            [{"label": "exploit",  "value_key": "http_exploit"}],
            [{"label": "purpose",  "value_key": "http_purpose_label"}],
            [{"label": "method",   "value_key": "http_method"},
             {"label": "path",     "value_key": "http_path",  "format": "truncate"}],
            [{"label": "body",     "value_key": "http_body",  "format": "truncate", "max_len": 40}],
        ],
        "scanner": [
            [{"label": "purpose",  "value_key": "http_purpose_label"}],
            [{"label": "scanner",  "value_key": "http_exploit"}],
            [{"label": "method",   "value_key": "http_method"},
             {"label": "path",     "value_key": "http_path",  "format": "truncate"}],
            [{"label": "body",     "value_key": "http_body",  "format": "truncate", "max_len": 40}],
        ],
    },
)
