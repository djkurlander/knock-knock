from protocol_api import Column, DisplayField, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="SNMP",
    proto_id=13,
    badge="SNMP",
    badge_color="#58b368",
    ui_order=110,
    honeypot_script="honeypots/snmp_honeypot.py",
    description="SNMP is used to monitor and manage network devices, and bots probe it for weak community strings.",
    default_enabled_entries=["SNMP:161"],
    supports_user_panel=False,
    supports_pass_panel=True,
    knock_table="knocks_snmp",
    columns=[
        Column("snmp_port",       "INTEGER"),
        Column("snmp_version",    "TEXT"),
        Column("snmp_community",  "TEXT"),
        Column("snmp_pdu",        "TEXT"),
        Column("snmp_request_id", "INTEGER"),
        Column("snmp_oid",        "TEXT"),
        Column("snmp_oid_count",  "INTEGER"),
        Column("snmp_set_value",  "TEXT"),
    ],
    passthrough_prefixes=["snmp_"],
    display_fields=[
        DisplayField("snmp_pdu",       "PDU"),
        DisplayField("snmp_oid",       "OID"),
        DisplayField("snmp_community", "Community"),
    ],
    display_formats={
        "snmp": [
            [
                {"label": "op",   "value_key": "snmp_pdu"},
                {"label": "count", "value_key": "snmp_oid_count"},
            ],
            [
                {"label": "oid",  "value_key": "snmp_oid", "format": "truncate", "max_len": 80},
            ],
            [
                {"label": "value", "value_key": "snmp_set_value", "format": "truncate", "max_len": 80},
            ],
            [
                {"label": "comm",  "value_key": "snmp_community", "format": "password"},
                {"label": "ver",   "value_key": "snmp_version"},
            ],
        ],
    },
    default_display_format="snmp",
)
