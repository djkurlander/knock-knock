import base64
import binascii
import email
import hashlib
import io
import os
import quopri
from email.generator import Generator

from protocol_api import Column, PassthroughField, ProtocolDefinition, TableDefinition


# Max body bytes retained (must match the honeypot's SMTP_MAX_BODY). 64 KB default.
SMTP_MAX_BODY = int(os.environ.get('SMTP_MAX_BODY', '65536'))
PREVIEW_LEN = 140   # readable feed preview length (matches the display truncate below)


# ---------------------------------------------------------------------------
# MIME-aware self-redaction
#
# The stored body is body-only (dedupable). A self-IP hidden inside a base64 or
# quoted-printable part is invisible to a literal redact, so we decode each part,
# redact via ctx['redact_self'], and re-encode in place. The invariant per-body
# Content-Type / Content-Transfer-Encoding (captured by the honeypot) tell us how.
# ---------------------------------------------------------------------------

def _decode_single(body, cte):
    """Decode a single-part body given its Content-Transfer-Encoding → text."""
    try:
        if cte == 'base64':
            b = ''.join(body.split())              # drop wrapping whitespace
            b = b[:len(b) - (len(b) % 4)]          # keep only complete 4-char groups
            return base64.b64decode(b).decode('utf-8', 'replace') if b else ''
        if cte == 'quoted-printable':
            return quopri.decodestring(body.encode('utf-8', 'replace')).decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        pass
    return body   # 7bit / 8bit / unknown → already text


def _encode_single(text, cte):
    """Re-encode redacted text in the same Content-Transfer-Encoding."""
    data = text.encode('utf-8', 'replace')
    if cte == 'base64':
        return base64.encodebytes(data).decode('ascii')
    if cte == 'quoted-printable':
        return quopri.encodestring(data).decode('ascii')
    return text


def _reencode_part(part, redacted_bytes):
    cte = (part.get('Content-Transfer-Encoding') or '').strip().lower()
    if cte == 'base64':
        part.set_payload(base64.encodebytes(redacted_bytes).decode('ascii'))
    elif cte == 'quoted-printable':
        part.set_payload(quopri.encodestring(redacted_bytes).decode('ascii'))
    else:
        part.set_payload(redacted_bytes.decode('utf-8', 'replace'))


def _bodyonly(msg):
    """Serialize a reconstructed message and drop the synthetic header block we
    prepended, yielding the redacted body-only content."""
    buf = io.StringIO()
    Generator(buf, mangle_from_=False, maxheaderlen=0).flatten(msg)
    s = buf.getvalue()
    idx = s.find('\n\n')
    return s[idx + 2:] if idx != -1 else s


def redact_body(body, content_type, transfer_encoding, redact):
    """Return (redacted_body_only, readable_preview). Falls back to a literal redact
    of the whole body if the MIME is absent or unparseable (dotted IPs cannot appear
    in the base64 alphabet, so a literal pass is always safe on encoded content)."""
    if not body:
        return body, (body or '')[:PREVIEW_LEN]
    literal = redact(body)
    ct = (content_type or '').strip()
    cte = (transfer_encoding or '').strip().lower()

    # Multipart: parse with the captured boundary, redact each leaf part, re-serialize.
    if ct.lower().startswith('multipart'):
        try:
            msg = email.message_from_string(
                f"Content-Type: {ct}\n\n{body}")
            changed = False
            preview = None
            for part in msg.walk():
                if part.is_multipart():
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode('utf-8', 'replace')
                red = redact(text)
                if preview is None and part.get_content_maintype() == 'text':
                    preview = red
                if red != text:
                    _reencode_part(part, red.encode('utf-8'))
                    changed = True
            if changed:
                out = redact(_bodyonly(msg))       # final literal pass (headers/plaintext)
                return out, (preview or out)[:PREVIEW_LEN]
            return literal, (preview or literal)[:PREVIEW_LEN]
        except Exception:
            return literal, literal[:PREVIEW_LEN]

    # Single part: decode → redact → re-encode only if something was hidden.
    decoded = _decode_single(body, cte)
    red = redact(decoded)
    if red == decoded:
        return literal, red[:PREVIEW_LEN]
    return _encode_single(red, cte), red[:PREVIEW_LEN]


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

def process_knock(knock, ctx):
    """Redact the body (MIME-aware), stash the full redacted body-only for db_update
    (db_only field, withheld from the feed) and replace knock['body'] with a short
    readable preview for the live feed."""
    # Idempotency for aggregation: a feeder already redacted + split this knock and
    # forwarded body_full (a db_only field rides the knock through the forward). The
    # aggregator re-runs process_knock, but knock['body'] is now the 140-char preview —
    # re-deriving from it would clobber the full body with the preview. If body_full is
    # already present the feeder did the work, so leave both fields untouched.
    if knock.get('body_full') is not None:
        return knock
    body = knock.get('body')
    if not body:
        return knock
    full, preview = redact_body(
        body, knock.get('smtp_content_type'), knock.get('smtp_transfer_encoding'),
        ctx['redact_self'])
    knock['body_full'] = full      # → smtp_body_intel (db_only, not fed)
    knock['body'] = preview        # → feed (passthrough)
    return knock


def db_update(data, cur, ctx):
    """Dedup the full redacted body into smtp_body_intel and link the knock via body_id."""
    rowid = ctx.get('knock_rowid')
    body_full = data.get('body_full')
    if not rowid or body_full is None:
        return
    now = ctx['now']
    sha = hashlib.sha256(body_full.encode('utf-8', 'replace')).hexdigest()
    cur.execute(
        """INSERT INTO smtp_body_intel (sha256, body, content_type, transfer_encoding,
                                        hits, first_seen, last_seen)
           VALUES (?, ?, ?, ?, 1, ?, ?)
           ON CONFLICT(sha256) DO UPDATE SET hits=hits+1, last_seen=excluded.last_seen""",
        (sha, body_full, data.get('smtp_content_type'), data.get('smtp_transfer_encoding'),
         now, now),
    )
    row = cur.execute("SELECT id FROM smtp_body_intel WHERE sha256=?", (sha,)).fetchone()
    if row:
        cur.execute("UPDATE knocks_smtp SET body_id=? WHERE id=?", (row[0], rowid))


DEFINITION = ProtocolDefinition(
    name="SMTP",
    proto_id=2,
    badge="SMTP",
    badge_color="#ff00ff",
    ui_order=80,
    honeypot_script="honeypots/smtp_honeypot.py",
    description="SMTP is the email protocol, which bots exploit to relay spam across the net.",
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
        Column("body_id",        "INTEGER"),   # → smtp_body_intel.id (full body deduped there)
    ],
    passthrough_prefixes=["smtp_"],
    passthrough_fields=[
        "subject",
        PassthroughField("body", sanitizer="body", max_len=SMTP_MAX_BODY),
    ],
    db_only_fields=["body_full"],
    process_knock="protocols.smtp:process_knock",
    db_update="protocols.smtp:db_update",
    extra_tables=[
        TableDefinition(
            name="smtp_body_intel",
            knock_linked=True,   # dependent side-table of knocks_smtp (via body_id); create only when SMTP is saved
            columns=[
                Column("id",                "INTEGER PRIMARY KEY AUTOINCREMENT"),
                Column("sha256",            "TEXT UNIQUE"),
                Column("body",              "TEXT"),
                Column("content_type",      "TEXT"),
                Column("transfer_encoding", "TEXT"),
                Column("hits",              "INTEGER"),
                Column("first_seen",        "DATETIME"),
                Column("last_seen",         "DATETIME"),
            ],
        ),
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
