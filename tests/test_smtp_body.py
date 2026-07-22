"""
Unit tests for the v3 SMTP body pipeline: MIME-aware self-redaction, the
smtp_body_intel dedup table + body_id linking, the db_only_fields channel, and the
backfill/migration tooling. In particular this locks the aggregation-idempotency
behaviour (a feeder forwards body_full; the aggregator must NOT re-derive it from the
already-truncated preview).
"""
import base64
import os
import quopri
import sqlite3
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'extras', 'db-migrations'))

import monitor
import protocols.smtp as smtp
from self_redaction import build_patterns_from_literals, apply_redaction
import smtp_body_backfill as bf

IP = "107.173.37.88"
_PATS = build_patterns_from_literals(ips=[IP])
def redact(s):
    return apply_redaction(s, _PATS)
CTX = {'redact_self': redact}


# --------------------------------------------------------------------------- redact_body

def _b64(text):
    return base64.encodebytes(text.encode()).decode()


def test_redact_body_plaintext_literal():
    full, preview = smtp.redact_body(f"relay test {IP} ok", "text/plain", "7bit", redact)
    assert IP not in full and "<target-ip>" in full
    assert IP not in preview


def test_redact_body_base64_hidden_ip():
    """The core leak: a self-IP encoded in a base64 part is invisible to a literal pass."""
    blob = _b64(f"connectivity confirmed for {IP} via open relay")
    assert IP not in blob                      # literally absent in the encoded form
    full, preview = smtp.redact_body(blob, "text/plain", "base64", redact)
    decoded = base64.b64decode(''.join(full.split())).decode()
    assert IP not in decoded                   # gone once decoded
    assert "<target-ip>" in preview


def test_redact_body_quoted_printable():
    full, _ = smtp.redact_body(f"ping=20{IP}=20done", "text/plain", "quoted-printable", redact)
    assert IP not in quopri.decodestring(full.encode()).decode()


def test_redact_body_multipart_base64_part():
    part = _b64(f"the ip is {IP} here")
    mp = (f'--B\r\nContent-Type: text/plain\r\n\r\nDear user\r\n'
          f'--B\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n{part}\r\n--B--\r\n')
    full, _ = smtp.redact_body(mp, 'multipart/mixed; boundary="B"', None, redact)
    leak = IP in full
    import re
    for chunk in re.findall(r'[A-Za-z0-9+/=\n]{16,}', full):
        try:
            if IP in base64.b64decode(''.join(chunk.split())).decode('utf-8', 'replace'):
                leak = True
        except Exception:
            pass
    assert not leak


def test_redact_body_deterministic():
    blob = _b64(f"relay {IP}")
    a, _ = smtp.redact_body(blob, "text/plain", "base64", redact)
    b, _ = smtp.redact_body(blob, "text/plain", "base64", redact)
    assert a == b                              # same input → same stored body (dedup key stable)


def test_redact_body_cross_feeder_dedup():
    """Two feeders, same campaign, different self-IPs → identical redacted body (so it
    dedups on the aggregator, and reversal is per-knock)."""
    redb = lambda s: apply_redaction(s, build_patterns_from_literals(ips=["5.6.7.8"]))
    a, _ = smtp.redact_body(_b64(f"confirmed {IP} relay"), "text/plain", "base64", redact)
    b, _ = smtp.redact_body(_b64("confirmed 5.6.7.8 relay"), "text/plain", "base64", redb)
    assert a == b


# --------------------------------------------------------------------------- process_knock

def test_process_knock_local_splits_body():
    body = f"open relay {IP} " + "x" * 300
    k = smtp.process_knock({'proto': 'SMTP', 'ip': '9.9.9.9', 'body': body,
                            'smtp_content_type': 'text/plain', 'smtp_transfer_encoding': '7bit'}, CTX)
    assert 'body_full' in k and len(k['body_full']) > len(k['body'])
    assert len(k['body']) <= 140
    assert IP not in k['body_full'] and IP not in k['body']


def test_process_knock_idempotent_across_aggregation():
    """Regression: a feeder forwards body_full; the aggregator re-runs process_knock and
    must keep the FULL body, not clobber it with the 140-char preview."""
    body = f"open relay verified for {IP}. " + "spam " * 60
    feeder = smtp.process_knock({'proto': 'SMTP', 'ip': '9.9.9.9', 'body': body,
                                 'smtp_content_type': 'text/plain', 'smtp_transfer_encoding': '7bit'}, CTX)
    full = feeder['body_full']
    assert len(full) > 140
    forwarded = {**feeder, 'source': 'la1'}           # body_full rides the forward
    agg = smtp.process_knock(forwarded, CTX)
    assert agg['body_full'] == full                   # preserved, not re-derived
    assert agg['body_full'] != agg['body']


def test_process_knock_no_body_is_noop():
    k = smtp.process_knock({'proto': 'SMTP', 'ip': '9.9.9.9', 'user': 'x', 'pass': 'y'}, CTX)
    assert 'body_full' not in k


# --------------------------------------------------------------------------- db_update / schema

def _db():
    # knocks_smtp + its knock-linked side-table smtp_body_intel — the pair the live monitor
    # provisions together when SMTP is saved (init_db, gated on TableDefinition.knock_linked).
    con = sqlite3.connect(":memory:")
    con.execute("""CREATE TABLE knocks_smtp (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                   ip_address TEXT, source INTEGER DEFAULT 0, smtp_rcpt_to TEXT, body_id INTEGER)""")
    con.execute("""CREATE TABLE smtp_body_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT UNIQUE,
                   body TEXT, content_type TEXT, transfer_encoding TEXT, hits INTEGER,
                   first_seen DATETIME, last_seen DATETIME)""")
    con.execute("""CREATE TABLE smtp_header_capture (knock_id INTEGER PRIMARY KEY,
                   headers TEXT NOT NULL, captured_at DATETIME NOT NULL)""")
    return con


def _save(con, knock):
    k = smtp.process_knock(dict(knock), CTX)
    cur = con.cursor()
    cur.execute("INSERT INTO knocks_smtp (timestamp, ip_address, source, smtp_rcpt_to, body_id) VALUES (?,?,?,?,NULL)",
                ("now", k['ip'], k.get('source', 0), k.get('smtp_rcpt_to')))
    smtp.db_update(k, cur, {'now': 'now', 'redact_self': redact, 'knock_rowid': cur.lastrowid})
    return cur.lastrowid, k


def test_db_update_dedup_and_body_id_link():
    con = _db()
    blob = _b64(f"open relay {IP}")
    r1, _ = _save(con, {'proto': 'SMTP', 'ip': '9.9.9.9', 'body': blob,
                        'smtp_content_type': 'text/plain', 'smtp_transfer_encoding': 'base64'})
    r2, _ = _save(con, {'proto': 'SMTP', 'ip': '9.9.9.9', 'body': blob,
                        'smtp_content_type': 'text/plain', 'smtp_transfer_encoding': 'base64'})
    r3, _ = _save(con, {'proto': 'SMTP', 'ip': '8.8.8.8', 'body': 'totally different body'})
    rows = con.execute("SELECT id, hits FROM smtp_body_intel ORDER BY id").fetchall()
    assert len(rows) == 2                                       # dup collapsed
    assert dict(rows)[con.execute("SELECT body_id FROM knocks_smtp WHERE id=?", (r1,)).fetchone()[0]] == 2
    b1 = con.execute("SELECT body_id FROM knocks_smtp WHERE id=?", (r1,)).fetchone()[0]
    b2 = con.execute("SELECT body_id FROM knocks_smtp WHERE id=?", (r2,)).fetchone()[0]
    b3 = con.execute("SELECT body_id FROM knocks_smtp WHERE id=?", (r3,)).fetchone()[0]
    assert b1 == b2 and b3 != b1                                # shared body_id vs distinct
    # stored body has no self-IP (literal or base64-decoded)
    stored = con.execute("SELECT body FROM smtp_body_intel WHERE id=?", (b1,)).fetchone()[0]
    assert IP not in base64.b64decode(''.join(stored.split())).decode('utf-8', 'replace')


def test_db_update_skips_without_rowid():
    con = _db()
    k = smtp.process_knock({'proto': 'SMTP', 'ip': '9.9.9.9', 'body': f"hi {IP}"}, CTX)
    smtp.db_update(k, con.cursor(), {'now': 'now', 'redact_self': redact, 'knock_rowid': None})
    assert con.execute("SELECT COUNT(*) FROM smtp_body_intel").fetchone()[0] == 0   # no orphan body row
    assert con.execute("SELECT COUNT(*) FROM smtp_header_capture").fetchone()[0] == 0


def test_db_update_header_capture_is_redacted_and_gated(monkeypatch):
    con = _db()
    cur = con.cursor()
    cur.execute("INSERT INTO knocks_smtp (timestamp, ip_address) VALUES ('now','9.9.9.9')")
    rowid = cur.lastrowid
    headers = f"Received: from mx.example ({IP})\nSubject: relay probe"
    k = smtp.process_knock({'proto': 'SMTP', 'ip': '9.9.9.9', 'smtp_headers': headers}, CTX)
    assert IP not in k['smtp_headers']
    assert '<target-ip>' in k['smtp_headers']

    monkeypatch.setattr(smtp, 'SMTP_SAVE_HEADERS', False)
    smtp.db_update(k, cur, {'now': 'now', 'redact_self': redact, 'knock_rowid': rowid})
    assert con.execute("SELECT COUNT(*) FROM smtp_header_capture").fetchone()[0] == 0

    monkeypatch.setattr(smtp, 'SMTP_SAVE_HEADERS', True)
    smtp.db_update(k, cur, {'now': 'now', 'redact_self': redact, 'knock_rowid': rowid})
    stored = con.execute("SELECT headers, captured_at FROM smtp_header_capture WHERE knock_id=?", (rowid,)).fetchone()
    assert stored == (f"Received: from mx.example (<target-ip>)\nSubject: relay probe", "now")


def test_db_update_coalesces_null_content_type_but_never_overwrites():
    con = _db()
    body = 'open relay probe'
    # 1. body first seen WITHOUT headers (backfill-style NULLs)
    _save(con, {'proto': 'SMTP', 'ip': '9.9.9.9', 'body': body})
    assert con.execute("SELECT content_type, transfer_encoding, hits FROM smtp_body_intel").fetchone() == (None, None, 1)
    # 2. matching knock WITH headers → COALESCE heals the NULLs, hits bumped
    _save(con, {'proto': 'SMTP', 'ip': '9.9.9.9', 'body': body,
                'smtp_content_type': 'text/plain', 'smtp_transfer_encoding': '7bit'})
    assert con.execute("SELECT content_type, transfer_encoding, hits FROM smtp_body_intel").fetchone() == ('text/plain', '7bit', 2)
    # 3. matching knock with DIFFERENT headers must NOT overwrite the set values
    _save(con, {'proto': 'SMTP', 'ip': '9.9.9.9', 'body': body,
                'smtp_content_type': 'text/html', 'smtp_transfer_encoding': '8bit'})
    assert con.execute("SELECT content_type, transfer_encoding, hits FROM smtp_body_intel").fetchone() == ('text/plain', '7bit', 3)


# --------------------------------------------------------------------------- db_only_fields

def test_body_full_is_db_only_not_passthrough():
    assert monitor._db_only_fields("SMTP") == ("body_full", "smtp_headers")
    fields, _prefixes = monitor._PASSTHROUGH_POLICIES["SMTP"]
    assert "body_full" not in fields            # must NOT be a passthrough (would hit the feed)
    assert "smtp_headers" not in fields
    passthrough = monitor._registered_passthrough_items({
        "proto": "SMTP",
        "smtp_headers": "Subject: x\nReceived: y",
        "smtp_mail_from": "a@example.test",
    })
    keys = [key for key, _value, _policy in passthrough]
    assert "smtp_headers" not in keys
    assert "smtp_mail_from" in keys


def test_smtp_definition_has_body_id_not_body():
    cols = {c.name for c in smtp.DEFINITION.columns}
    assert "body_id" in cols and "body" not in cols
    assert any(t.name == "smtp_body_intel" for t in smtp.DEFINITION.extra_tables)
    assert any(t.name == "smtp_header_capture" for t in smtp.DEFINITION.extra_tables)


def test_smtp_body_intel_is_knock_linked():
    # smtp_body_intel is a dependent side-table of knocks_smtp (body_id FK), so it must be
    # marked knock_linked → init_db/updatedb create it only when SMTP is saved.
    for table_name in ("smtp_body_intel", "smtp_header_capture"):
        tbl = next(t for t in smtp.DEFINITION.extra_tables if t.name == table_name)
        assert tbl.knock_linked is True


# --------------------------------------------------------------------------- backfill

def test_backfill_base64_and_scoping_and_idempotent():
    con = sqlite3.connect(":memory:")
    con.execute("""CREATE TABLE knocks_smtp (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                   source INTEGER DEFAULT 0, body TEXT, body_id INTEGER)""")
    blob = _b64(f"open relay {IP}")
    for src, body in [(0, blob), (0, blob), (0, f"plain {IP}"), (3, f"feeder {IP}")]:
        con.execute("INSERT INTO knocks_smtp (timestamp, source, body) VALUES ('t',?,?)", (src, body))
    con.commit()
    done = bf.backfill(con, redact, where_extra="AND source=0")
    assert done == 3
    # local scrubbed + linked; feeder row untouched
    assert con.execute("SELECT COUNT(*) FROM knocks_smtp WHERE source=0 AND body IS NULL AND body_id IS NOT NULL").fetchone()[0] == 3
    assert con.execute("SELECT body FROM knocks_smtp WHERE source=3").fetchone()[0] is not None
    # no self-IP anywhere in stored bodies (incl. base64 fix)
    for (b,) in con.execute("SELECT body FROM smtp_body_intel"):
        dec = b
        try:
            dec = base64.b64decode(''.join(b.split())).decode('utf-8', 'replace')
        except Exception:
            pass
        assert IP not in b and IP not in dec
    assert bf.backfill(con, redact, where_extra="AND source=0") == 0    # idempotent
    assert bf.pending(con, "AND source!=0") == 1                         # feeder still deferred


def test_maybe_drop_body_column_gated_on_global_pending():
    con = sqlite3.connect(":memory:")
    con.execute("""CREATE TABLE knocks_smtp (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                   source INTEGER DEFAULT 0, body TEXT, body_id INTEGER)""")
    for src, body in [(0, f"local {IP}"), (0, f"local {IP} two"), (3, f"feeder {IP}")]:
        con.execute("INSERT INTO knocks_smtp (timestamp, source, body) VALUES ('t',?,?)", (src, body))
    con.commit()

    # local backfilled, feeder still pending → must NOT drop (aggregator safety)
    bf.backfill(con, redact, where_extra="AND source=0")
    assert bf.pending(con) == 1
    assert bf.maybe_drop_body_column(con) is False
    assert "body" in bf._columns(con, "knocks_smtp")

    # all backfilled → pending 0, but keep=True must still NOT drop
    bf.backfill(con, redact)
    assert bf.pending(con) == 0
    assert bf.maybe_drop_body_column(con, keep=True) is False
    assert "body" in bf._columns(con, "knocks_smtp")

    if sqlite3.sqlite_version_info < (3, 35, 0):
        pytest.skip("DROP COLUMN needs SQLite >= 3.35")
    # default → drops now that global pending is 0
    assert bf.maybe_drop_body_column(con) is True
    assert "body" not in bf._columns(con, "knocks_smtp")
    assert "body_id" in bf._columns(con, "knocks_smtp")
