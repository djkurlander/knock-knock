from protocol_api import Column, FieldMap, PassthroughField, ProtocolDefinition


DEFINITION = ProtocolDefinition(
    name="SMTP",
    proto_id=2,
    badge="SMTP",
    badge_color="#ff00ff",
    ui_order=80,
    honeypot_script="honeypots/smtp_honeypot.py",
    description="SMTP is the email protocol, which bots exploit to relay spam across the net.",
    ports_label="ports 25, 587",
    default_enabled_entries=["SMTP:25", "SMTP:587"],
    supports_user_panel=True,
    supports_pass_panel=True,
    knock_table="knocks_smtp",
    columns=[
        Column("username",       "TEXT"),
        Column("password",       "TEXT"),
        Column("smtp_port",      "INTEGER"),
        Column("smtp_stage",     "TEXT"),
        Column("smtp_mail_from", "TEXT"),
        Column("smtp_rcpt_to",   "TEXT"),
        Column("subject",        "TEXT"),
        Column("body",           "TEXT"),
    ],
    field_map=[
        FieldMap("user", "username"),
        FieldMap("pass", "password"),
    ],
    passthrough_prefixes=["smtp_"],
    passthrough_fields=[
        "subject",
        PassthroughField("body", sanitizer="body"),
    ],
    display_formats={
        "auth": [
            [{"label": "user",     "value_key": "user", "format": "username"},
             {"label": "password", "value_key": "pass", "format": "password"}],
        ],
        "message": [
            [{"label": "from",    "value_key": "smtp_mail_from"}],
            [{"label": "to",      "value_key": "smtp_rcpt_to"}],
            [{"label": "subject", "value_key": "subject"}],
            [{"label": "body",    "value_key": "body", "format": "truncate", "max_len": 140}],
        ],
    },
)
