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
)
