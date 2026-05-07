from protocol_api import Column, DisplayField, FieldMap, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="MQTT",
    proto_id=9,
    badge="MQTT",
    badge_color="#35c7b7",
    ui_order=90,
    honeypot_script="honeypots/mqtt_honeypot.py",
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
        Column("mqtt_signature", "TEXT"),
        Column("mqtt_purpose", "TEXT"),
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
        DisplayField("mqtt_signature", "Signature"),
    ],
    display_formats={
        "connect": [
            [
                {"label": "action", "value": "connect"},
                {"label": "client", "value_key": "mqtt_client_id"},
            ],
            [
                {"label": "version", "value_key": "mqtt_version"},
                {"label": "auth", "value_key": "mqtt_auth_result"},
            ],
        ],
        "malformed_connect": [
            [
                {"label": "action", "value": "malformed connect"},
                {"label": "error", "value_key": "mqtt_parse_error", "format": "truncate"},
            ],
        ],
        "non_connect": [
            [
                {"label": "action", "value": "protocol probe"},
                {"label": "packet", "value_key": "mqtt_packet_type"},
            ],
            [
                {"label": "valid", "value_key": "mqtt_packet_valid", "format": "boolean"},
                {"label": "bytes", "value_key": "mqtt_remaining_length"},
            ],
        ],
        "subscribe": [
            [
                {"label": "action", "value": "subscribe"},
                {"label": "client", "value_key": "mqtt_client_id"},
            ],
            [
                {"label": "topic", "value_key": "mqtt_topic", "format": "code"},
                {"label": "qos", "value_key": "mqtt_qos"},
            ],
        ],
        "publish": [
            [
                {"label": "action", "value": "publish"},
                {"label": "client", "value_key": "mqtt_client_id"},
            ],
            [
                {"label": "topic", "value_key": "mqtt_topic", "format": "code"},
                {"label": "qos", "value_key": "mqtt_qos"},
                {"label": "bytes", "value_key": "mqtt_payload_len"},
            ],
        ],
        "pingreq": [
            [
                {"label": "action", "value": "ping"},
                {"label": "client", "value_key": "mqtt_client_id"},
                {"label": "count", "value_key": "mqtt_pingreq_count"},
            ],
        ],
        "packet": [
            [
                {"label": "packet", "value_key": "mqtt_packet_type"},
                {"label": "client", "value_key": "mqtt_client_id"},
            ],
            [
                {"label": "valid", "value_key": "mqtt_packet_valid", "format": "boolean"},
                {"label": "bytes", "value_key": "mqtt_remaining_length"},
            ],
        ],
    },
    display_format_field="mqtt_stage",
)
