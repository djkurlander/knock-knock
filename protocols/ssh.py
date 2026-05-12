from protocol_api import Column, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="SSH",
    proto_id=0,
    badge="SSH",
    badge_color="#00ff41",
    ui_order=10,
    honeypot_script="honeypots/ssh_honeypot_asyncssh.py",
    description="SSH allows humans and bots to log into remote servers.",
    default_enabled_entries=["SSH"],
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_ssh",
    columns=[
        Column("username", "TEXT"),
        Column("password", "TEXT"),
    ],
    display_formats={
        "ssh": [
            [
                {"label": "user", "value_key": "user", "format": "username"},
                {"label": "password", "value_key": "pass", "format": "password"},
            ],
        ],
    },
    default_display_format="ssh",
)
