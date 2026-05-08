from protocol_api import Column, FieldMap, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="TNET",
    proto_id=1,
    badge="TNET",
    badge_color="#00fbff",
    ui_order=20,
    honeypot_script="honeypots/telnet_honeypot.py",
    default_enabled_entries=["TNET"],
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_tnet",
    columns=[
        Column("username", "TEXT"),
        Column("password", "TEXT"),
    ],
    field_map=[
        FieldMap("user", "username"),
        FieldMap("pass", "password"),
    ],
    display_formats={
        "tnet": [
            [
                {"label": "user", "value_key": "user", "format": "username"},
                {"label": "password", "value_key": "pass", "format": "password"},
            ],
        ],
    },
    default_display_format="tnet",
)
