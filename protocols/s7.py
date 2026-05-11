from protocol_api import Column, DisplayField, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="S7",
    proto_id=12,
    badge="S7",
    badge_color="#009fdb",
    ui_order=105,
    honeypot_script="honeypots/s7_honeypot.py",
    description="Siemens S7 is a protocol used by Siemens PLCs in industrial control systems.",
    ports_label="port 102",
    default_enabled_entries=["S7:102"],
    supports_user_panel=False,
    supports_pass_panel=False,
    knock_table="knocks_s7",
    columns=[
        Column("s7_port",          "INTEGER"),
        Column("s7_function",      "INTEGER"),
        Column("s7_function_name", "TEXT"),
        Column("s7_area",          "TEXT"),
        Column("s7_db_number",     "INTEGER"),
        Column("s7_szl_id",        "TEXT"),
    ],
    passthrough_prefixes=["s7_"],
    display_fields=[
        DisplayField("s7_function_name", "Function"),
        DisplayField("s7_area",          "Area"),
    ],
    display_formats={
        "identify": [
            [
                {"label": "code", "value_key": "s7_function_name"},
                {"label": "szl",  "value_key": "s7_szl_id"},
            ],
        ],
        "read": [
            [
                {"label": "code", "value_key": "s7_function_name"},
                {"label": "area", "value_key": "s7_area"},
                {"label": "db",   "value_key": "s7_db_number"},
            ],
        ],
        "write": [
            [
                {"label": "code", "value_key": "s7_function_name"},
                {"label": "area", "value_key": "s7_area"},
                {"label": "db",   "value_key": "s7_db_number"},
            ],
        ],
        "transfer": [
            [
                {"label": "code", "value_key": "s7_function_name"},
            ],
        ],
        "other": [
            [
                {"label": "code", "value_key": "s7_function_name"},
            ],
        ],
    },
    default_display_format="identify",
)
