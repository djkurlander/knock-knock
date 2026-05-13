from protocol_api import Column, DisplayField, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="S7",
    proto_id=12,
    badge="S7",
    badge_color="#009fdb",
    ui_order=105,
    honeypot_script="honeypots/s7_honeypot.py",
    description="Siemens S7 is a protocol used by Siemens PLCs in industrial control systems.",
    default_enabled_entries=["S7:102"],
    supports_user_panel=False,
    supports_pass_panel=False,
    knock_table="knocks_s7",
    columns=[
        Column("tcp102_protocol",  "TEXT"),
        Column("tcp102_raw_prefix", "TEXT"),
        Column("s7_port",          "INTEGER"),
        Column("s7_function",      "INTEGER"),
        Column("s7_function_name", "TEXT"),
        Column("s7_area",          "TEXT"),
        Column("s7_db_number",     "INTEGER"),
        Column("s7_szl_id",        "TEXT"),
        Column("mms_message",      "TEXT"),
        Column("mms_oid",          "TEXT"),
    ],
    passthrough_prefixes=["tcp102_", "s7_", "mms_"],
    display_fields=[
        DisplayField("s7_function_name", "Function"),
        DisplayField("s7_area",          "Area"),
    ],
    display_formats={
        "identify": [
            [
                {"label": "proto", "value_key": "tcp102_protocol"},
                {"label": "code", "value_key": "s7_function_name"},
                {"label": "szl",  "value_key": "s7_szl_id"},
            ],
        ],
        "read": [
            [
                {"label": "proto", "value_key": "tcp102_protocol"},
                {"label": "code", "value_key": "s7_function_name"},
                {"label": "area", "value_key": "s7_area"},
                {"label": "db",   "value_key": "s7_db_number"},
            ],
        ],
        "write": [
            [
                {"label": "proto", "value_key": "tcp102_protocol"},
                {"label": "code", "value_key": "s7_function_name"},
                {"label": "area", "value_key": "s7_area"},
                {"label": "db",   "value_key": "s7_db_number"},
            ],
        ],
        "transfer": [
            [
                {"label": "proto", "value_key": "tcp102_protocol"},
                {"label": "code", "value_key": "s7_function_name"},
            ],
        ],
        "other": [
            [
                {"label": "proto", "value_key": "tcp102_protocol"},
                {"label": "code", "value_key": "s7_function_name"},
            ],
            [
                {"label": "likely", "value_key": "s7_protocol_guess"},
            ],
            [
                {"label": "hex", "value_key": "s7_raw_prefix", "format": "truncate", "max_len": 20},
            ],
        ],
        "mms": [
            [
                {"label": "proto", "value_key": "tcp102_protocol"},
                {"label": "msg",   "value_key": "mms_message"},
            ],
            [
                {"label": "oid", "value_key": "mms_oid"},
            ],
            [
                {"label": "hex", "value_key": "tcp102_raw_prefix", "format": "truncate", "max_len": 20},
            ],
        ],
    },
    default_display_format="identify",
)
