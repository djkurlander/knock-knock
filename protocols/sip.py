from protocol_api import Column, ProtocolDefinition, TableDefinition


def after_save(knock, package, ctx):
    caller = knock.get('sip_extension') or knock.get('sip_auth_user') or knock.get('sip_uri_user')
    if caller:
        package['sip_caller'] = caller


def db_update(data, cur, ctx):
    country      = data.get('sip_dial_country')
    country_name = data.get('sip_dial_country_name')
    dial_number  = data.get('sip_dial_number')
    if dial_number:
        now = ctx['now']
        cur.execute(
            """INSERT INTO dial_intel VALUES (?, 1, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(number) DO UPDATE SET hits=hits+1, last_seen=?, country_name=?""",
            (dial_number, now, now, country, country_name,
             data.get('sip_dial_lat'), data.get('sip_dial_lng'), now, country_name),
        )


DEFINITION = ProtocolDefinition(
    name="SIP",
    proto_id=6,
    badge="SIP",
    badge_color="#ff7a00",
    ui_order=60,
    honeypot_script="honeypots/sip_honeypot.py",
    description="SIP allows humans and bots to make phone calls.",
    ports_label="port 5060",
    default_enabled_entries=["SIP"],
    supports_user_panel=False,
    supports_pass_panel=False,
    knock_table="knocks_sip",
    columns=[
        Column("sip_method",            "TEXT"),
        Column("sip_dial_string",       "TEXT"),
        Column("sip_dial_number",       "TEXT"),
        Column("sip_call_id",           "TEXT"),
        Column("sip_cseq",              "TEXT"),
        Column("sip_extension",         "TEXT"),
        Column("sip_dial_country",      "TEXT"),
        Column("sip_dial_country_name", "TEXT"),
        Column("sip_dial_lat",          "REAL"),
        Column("sip_dial_lng",          "REAL"),
    ],
    passthrough_prefixes=["sip_"],
    after_save="protocols.sip:after_save",
    db_update="protocols.sip:db_update",
    extra_tables=[
        TableDefinition(
            name="dial_intel",
            columns=[
                Column("number",       "TEXT PRIMARY KEY"),
                Column("hits",         "INTEGER"),
                Column("first_seen",   "DATETIME"),
                Column("last_seen",    "DATETIME"),
                Column("country",      "TEXT"),
                Column("country_name", "TEXT"),
                Column("lat",          "REAL"),
                Column("lng",          "REAL"),
            ],
        ),
    ],
    display_formats={
        "sip": [
            [{"label": "from",         "value_key": "sip_caller"}],
            [{"label": "dialing",      "value_key": "sip_dial_string"}],
            [{"label": "toll call to", "value_key": "sip_dial_country_name", "flag_key": "sip_dial_country"}],
        ],
    },
    default_display_format="sip",
)
