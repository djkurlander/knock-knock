from protocol_api import Column, DisplayField, FieldMap, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="MQTT",
    proto_id=9,
    badge="MQTT",
    badge_color="#35c7b7",
    ui_order=90,
    honeypot_script="honeypots/mqtt_honeypot.py",
    description="MQTT is a protocol used by IoT and other devices to send updates and receive commands.",
    ports_label="ports 1883, 8883",
    default_enabled_entries=["MQTT:1883", "MQTT:8883:TLS"],
    option_args={
        "TLS": ["--ssl"],
    },
    option_env={
        "OPEN": {"MQTT_AUTH_MODE": "open"},
        "REQUIRE": {"MQTT_AUTH_MODE": "require"},
        "REJECT": {"MQTT_AUTH_MODE": "reject"},
    },
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_mqtt",
    columns=[
        Column("username", "TEXT"),
        Column("password", "TEXT"),
        Column("mqtt_port", "INTEGER"),
        Column("mqtt_tls", "INTEGER"),
        Column("mqtt_stage", "TEXT"),
        Column("mqtt_packet_type", "TEXT"),
        Column("mqtt_packet_valid", "INTEGER"),
        Column("mqtt_client_id", "TEXT"),
        Column("mqtt_protocol_name", "TEXT"),
        Column("mqtt_version", "TEXT"),
        Column("mqtt_keepalive", "INTEGER"),
        Column("mqtt_scanner", "TEXT"),
        Column("mqtt_exploit", "TEXT"),
    ],
    field_map=[
        FieldMap("user", "username"),
        FieldMap("pass", "password"),
    ],
    passthrough_prefixes=["mqtt_"],
    display_fields=[
        DisplayField("mqtt_stage", "Stage"),
        DisplayField("mqtt_client_id", "Client ID"),
        DisplayField("mqtt_version", "Version"),
        DisplayField("mqtt_packet_type", "Packet"),
        DisplayField("mqtt_scanner", "Scanner"),
    ],
    display_formats={
        "connect": [
            [
                {"label": "exploit", "value_key": "mqtt_exploit"},
            ],
            [
                {"label": "type",    "value_key": "mqtt_stage"},
                {"label": "version", "value_key": "mqtt_version"},
            ],
            # No format — row is suppressed entirely when user/pass are absent (anonymous connects).
            # format:"username"/"password" would show n/a even for missing fields, which we don't want here.
            [
                {"label": "user", "value_key": "user"},
                {"label": "pass", "value_key": "pass"},
            ],
            [
                {"label": "client",  "value_key": "mqtt_client_id"},
                {"label": "scanner", "value_key": "mqtt_scanner", "format": "truncate"},
            ],
        ],
        "malformed_connect": [
            [
                {"label": "exploit", "value_key": "mqtt_exploit"},
            ],
            [
                {"label": "type",    "value_key": "mqtt_stage"},
                {"label": "error",   "value_key": "mqtt_parse_error", "format": "truncate"},
                {"label": "scanner", "value_key": "mqtt_scanner", "format": "truncate"},
            ],
        ],
        "non_connect": [
            [
                {"label": "exploit", "value_key": "mqtt_exploit"},
            ],
            [
                {"label": "type",    "value_key": "mqtt_stage"},
                {"label": "packet",  "value_key": "mqtt_packet_type"},
                {"label": "scanner", "value_key": "mqtt_scanner", "format": "truncate"},
            ],
        ],
        "session": [
            [
                {"label": "exploit", "value_key": "mqtt_exploit"},
            ],
            [
                {"label": "type",  "value_key": "mqtt_stage"},
                {"label": "topic", "value_key": "mqtt_topic", "max_len": 80},
            ],
            [
                {"label": "client",  "value_key": "mqtt_client_id"},
                {"label": "scanner", "value_key": "mqtt_scanner", "format": "truncate"},
                {"label": "count",   "value_key": "mqtt_pingreq_count"},
            ],
        ],
        "other": [
            [
                {"label": "exploit", "value_key": "mqtt_exploit"},
            ],
            [
                {"label": "type", "value_key": "mqtt_stage"},
                {"label": "packet", "value_key": "mqtt_packet_type"},
            ],
            [
                {"label": "client",  "value_key": "mqtt_client_id"},
                {"label": "scanner", "value_key": "mqtt_scanner", "format": "truncate"},
            ],
        ],
    },
    display_format_field="mqtt_stage",
)
