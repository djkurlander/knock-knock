from protocol_api import Column, FieldMap, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="SMB",
    proto_id=7,
    badge="SMB",
    badge_color="#d6d9df",
    ui_order=50,
    honeypot_script="honeypots/smb_honeypot.py",
    default_enabled_entries=["SMB"],
    supports_user_panel=True,
    supports_pass_panel=False,
    knock_table="knocks_smb",
    columns=[
        Column("username",    "TEXT"),
        Column("smb_action",  "TEXT"),
        Column("smb_share",   "TEXT"),
        Column("smb_file",    "TEXT"),
        Column("smb_version", "TEXT"),
        Column("smb_domain",  "TEXT"),
        Column("smb_host",    "TEXT"),
    ],
    field_map=[
        FieldMap("user", "username"),
    ],
    passthrough_prefixes=["smb_"],
    display_formats={
        "probe": [
            [{"label": "action",  "value_key": "smb_action"}],
        ],
        "auth": [
            [{"label": "action",  "value_key": "smb_action"},
             {"label": "user",    "value_key": "user",       "format": "username"},
             {"label": "domain",  "value_key": "smb_domain"},
             {"label": "host",    "value_key": "smb_host"},
             {"label": "version", "value_key": "smb_version"}],
        ],
        "connect": [
            [{"label": "action",  "value_key": "smb_action"},
             {"label": "share",   "value_key": "smb_share"}],
        ],
        "list_shares": [
            [{"label": "action",  "value_key": "smb_action"},
             {"label": "shares",  "value_key": "smb_share"}],
        ],
        "service_op": [
            [{"label": "action",  "value_key": "smb_action"},
             {"label": "svc",     "value_key": "smb_service_name"},
             {"label": "path",    "value_key": "smb_file"}],
        ],
        "file_op": [
            [{"label": "action",  "value_key": "smb_action"},
             {"label": "share",   "value_key": "smb_share"},
             {"label": "file",    "value_key": "smb_file"}],
        ],
        "list_files": [
            [{"label": "action",  "value_key": "smb_action"},
             {"label": "share",   "value_key": "smb_share"},
             {"label": "dir",     "value_key": "smb_file"}],
        ],
    },
)
