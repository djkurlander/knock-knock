from protocol_api import Column, DisplayField, FieldMap, PassthroughField, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="NRED",
    proto_id=10,
    badge="NRED",
    badge_color="#d95f5f",
    ui_order=95,
    honeypot_script="honeypots/node_red_honeypot.py",
    default_enabled_entries=["NRED:1880"],
    option_args={
        "TLS": ["--ssl"],
    },
    option_env={
        "OPEN": {"NRED_AUTH_MODE": "open"},
        "REQUIRE": {"NRED_AUTH_MODE": "require"},
        "FAKE_TOKEN": {"NRED_AUTH_MODE": "fake_token"},
    },
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_nred",
    columns=[
        Column("username", "TEXT"),
        Column("password", "TEXT"),
        Column("nred_port", "INTEGER"),
        Column("nred_method", "TEXT"),
        Column("nred_path", "TEXT"),
        Column("nred_exploit", "TEXT"),
        Column("nred_host", "TEXT"),
        Column("nred_user_agent", "TEXT"),
        Column("nred_auth_mode", "TEXT"),
        Column("nred_body", "TEXT"),
    ],
    field_map=[
        FieldMap("user", "username"),
        FieldMap("pass", "password"),
    ],
    passthrough_prefixes=["nred_"],
    passthrough_fields=[
        PassthroughField("nred_body", sanitizer="body", max_len=2000),
    ],
    display_fields=[
        DisplayField("nred_exploit", "Exploit"),
        DisplayField("nred_method", "Method"),
        DisplayField("nred_path", "Path"),
    ],
    display_formats={
        "request": [
            [
                {"label": "exploit", "value_key": "nred_exploit"},
            ],
            [
                {"label": "method", "value_key": "nred_method"},
                {"label": "path",   "value_key": "nred_path", "format": "truncate"},
            ],
        ],
        "auth": [
            [
                {"label": "exploit", "value_key": "nred_exploit"},
            ],
            # No format — row suppressed when credentials absent (same pattern as MQTT connect)
            [
                {"label": "user", "value_key": "user"},
                {"label": "pass", "value_key": "pass"},
            ],
            [
                {"label": "grant",  "value_key": "nred_grant_type"},
                {"label": "client", "value_key": "nred_client_id"},
            ],
            [
                {"label": "method", "value_key": "nred_method"},
                {"label": "path",   "value_key": "nred_path", "format": "truncate"},
            ],
        ],
        "flow": [
            [
                {"label": "exploit", "value_key": "nred_exploit"},
            ],
            [
                {"label": "nodes", "value_key": "nred_flow_node_count"},
                {"label": "exec",  "value_key": "nred_flow_has_exec", "format": "boolean"},
                {"label": "mqtt",  "value_key": "nred_flow_has_mqtt", "format": "boolean"},
            ],
            [
                {"label": "method", "value_key": "nred_method"},
                {"label": "path",   "value_key": "nred_path", "format": "truncate"},
            ],
        ],
        "exploit": [
            [
                {"label": "exploit", "value_key": "nred_exploit"},
            ],
            [
                {"label": "method", "value_key": "nred_method"},
                {"label": "path",   "value_key": "nred_path", "format": "truncate"},
            ],
        ],
    },
    default_display_format="request",
)
