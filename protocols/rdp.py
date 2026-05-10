from protocol_api import Column, FieldMap, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="RDP",
    proto_id=3,
    badge="RDP",
    badge_color="#ff1a1a",
    ui_order=40,
    honeypot_script="honeypots/rdp_honeypot.py",
    description="RDP supports logging in with a virtual desktop, usually on Windows.",
    ports_label="port 3389",
    default_enabled_entries=["RDP"],
    supports_user_panel=True,
    supports_pass_panel=False,
    knock_table="knocks_rdp",
    columns=[
        Column("username", "TEXT"),
        Column("rdp_source", "TEXT"),
        Column("domain", "TEXT"),
        Column("rdp_workstation", "TEXT"),
    ],
    field_map=[
        FieldMap("user", "username"),
        FieldMap("rdp_source", "rdp_source"),
        FieldMap("domain", "domain"),
        FieldMap("rdp_workstation", "rdp_workstation"),
    ],
    passthrough_fields=[
        "domain",
        "rdp_source",
        "rdp_workstation",
    ],
    display_formats={
        "rdp": [
            [
                {"label": "user", "value_key": "user", "format": "username"},
                {"label": "domain", "value_key": "domain"},
                {"label": "host", "value_key": "rdp_workstation"},
            ],
        ],
    },
    default_display_format="rdp",
)
