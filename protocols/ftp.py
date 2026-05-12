from protocol_api import Column, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="FTP",
    proto_id=5,
    badge="FTP",
    badge_color="#FFFF77",
    ui_order=30,
    honeypot_script="honeypots/ftp_honeypot.py",
    description="FTP is a legacy protocol, allowing files to be accessed remotely.",
    default_enabled_entries=["FTP"],
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_ftp",
    columns=[
        Column("username", "TEXT"),
        Column("password", "TEXT"),
    ],
    display_formats={
        "ftp": [
            [
                {"label": "user", "value_key": "user", "format": "username"},
                {"label": "password", "value_key": "pass", "format": "password"},
            ],
        ],
    },
    default_display_format="ftp",
)
