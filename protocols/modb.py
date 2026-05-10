from protocol_api import Column, DisplayField, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="MODB",
    proto_id=11,
    badge="MODB",
    badge_color="#e8a020",
    ui_order=100,
    honeypot_script="honeypots/modbus_honeypot.py",
    default_enabled_entries=["MODB:502"],
    supports_user_panel=False,
    supports_pass_panel=False,
    knock_table="knocks_modb",
    columns=[
        Column("modb_port",        "INTEGER"),
        Column("modb_unit_id",     "INTEGER"),
        Column("modb_fc",          "INTEGER"),
        Column("modb_fc_name",     "TEXT"),
        Column("modb_address",     "INTEGER"),
        Column("modb_quantity",    "INTEGER"),
        Column("modb_write_value", "TEXT"),
        Column("modb_write_data",  "TEXT"),
    ],
    passthrough_prefixes=["modb_"],
    display_fields=[
        DisplayField("modb_fc_name",  "Function"),
        DisplayField("modb_address",  "Address"),
        DisplayField("modb_quantity", "Quantity"),
    ],
    display_formats={
        "read": [
            [
                {"label": "fc",   "value_key": "modb_fc_name"},
                {"label": "unit", "value_key": "modb_unit_id"},
                {"label": "addr", "value_key": "modb_address"},
                {"label": "qty",  "value_key": "modb_quantity"},
            ],
        ],
        "write": [
            [
                {"label": "fc",    "value_key": "modb_fc_name"},
                {"label": "unit",  "value_key": "modb_unit_id"},
                {"label": "addr",  "value_key": "modb_address"},
                {"label": "value", "value_key": "modb_write_value"},
            ],
            [
                {"label": "qty",  "value_key": "modb_quantity"},
                {"label": "data", "value_key": "modb_write_data", "format": "truncate"},
            ],
        ],
        "identify": [
            [
                {"label": "fc",   "value_key": "modb_fc_name"},
                {"label": "unit", "value_key": "modb_unit_id"},
            ],
        ],
        "other": [
            [
                {"label": "fc",   "value_key": "modb_fc_name"},
                {"label": "unit", "value_key": "modb_unit_id"},
            ],
        ],
    },
    default_display_format="read",
)
