"""
Unit tests for pure helper functions.

No network connections, Redis, SQLite, or subprocess spawning — these
functions are tested in isolation and cannot affect the DB or UI.
"""
import os
import sqlite3
import sys
import time

# Make repo root and honeypots/ importable
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'honeypots'))

from common import normalize_ip, extract_addr, smtp_tls_cert_subject
from ip_ban import fmt_ban_until
from ssh_honeypot_asyncssh import _clamp_delay_bounds
import sip_b2bua
import sip_honeypot
import monitor
from monitor import sanitize_credential, sanitize_body, _parse_protocol_entry, ProtocolEntry


# ---------------------------------------------------------------------------
# common.normalize_ip
# ---------------------------------------------------------------------------

def test_normalize_ip_passthrough():
    assert normalize_ip('1.2.3.4') == '1.2.3.4'

def test_normalize_ip_ipv4_mapped():
    assert normalize_ip('::ffff:1.2.3.4') == '1.2.3.4'

def test_normalize_ip_plain_ipv6():
    assert normalize_ip('2001:db8::1') == '2001:db8::1'

def test_normalize_ip_empty():
    assert normalize_ip('') == ''

def test_normalize_ip_none():
    assert normalize_ip(None) is None


# ---------------------------------------------------------------------------
# common.extract_addr
# ---------------------------------------------------------------------------

def test_extract_addr_angle_brackets():
    assert extract_addr('MAIL FROM:<foo@bar.com>') == 'foo@bar.com'

def test_extract_addr_empty_angle_brackets():
    assert extract_addr('MAIL FROM:<>') == '<none>'

def test_extract_addr_no_brackets():
    assert extract_addr('foo@bar.com') == 'foo@bar.com'

def test_extract_addr_strips_whitespace():
    assert extract_addr('  <user@host.com>  ') == 'user@host.com'


# ---------------------------------------------------------------------------
# common.smtp_tls_cert_subject
# ---------------------------------------------------------------------------

def test_smtp_tls_cert_subject_normal():
    assert smtp_tls_cert_subject('mail.example.com') == '/CN=mail.example.com/O=Postfix/C=US'

def test_smtp_tls_cert_subject_long_hostname_truncated():
    long = 'a' * 100
    subj = smtp_tls_cert_subject(long)
    cn = subj.split('/CN=')[1].split('/')[0]
    assert len(cn) <= 64

def test_smtp_tls_cert_subject_none_fallback():
    subj = smtp_tls_cert_subject(None)
    assert '/CN=mail.local' in subj


# ---------------------------------------------------------------------------
# ip_ban.fmt_ban_until
# ---------------------------------------------------------------------------

def test_fmt_ban_until_none():
    assert fmt_ban_until(None) == 'not banned'

def test_fmt_ban_until_permanent():
    assert fmt_ban_until(0) == 'permanent'

def test_fmt_ban_until_expired():
    past = int(time.time()) - 3600
    result = fmt_ban_until(past)
    assert 'expired' in result

def test_fmt_ban_until_active():
    future = int(time.time()) + 86400 * 5
    result = fmt_ban_until(future)
    assert 'until' in result
    assert '5d' in result


# ---------------------------------------------------------------------------
# ssh_honeypot_asyncssh._clamp_delay_bounds
# ---------------------------------------------------------------------------

def test_clamp_delay_bounds_normal():
    assert _clamp_delay_bounds(200, 600) == (200, 600)

def test_clamp_delay_bounds_reversed():
    assert _clamp_delay_bounds(600, 200) == (200, 600)

def test_clamp_delay_bounds_negative_clamped():
    assert _clamp_delay_bounds(-50, 100) == (0, 100)

def test_clamp_delay_bounds_both_zero():
    assert _clamp_delay_bounds(0, 0) == (0, 0)


# ---------------------------------------------------------------------------
# monitor.sanitize_credential
# ---------------------------------------------------------------------------

def test_sanitize_credential_normal():
    assert sanitize_credential('hunter2') == 'hunter2'

def test_sanitize_credential_none():
    assert sanitize_credential(None) is None

def test_sanitize_credential_empty():
    assert sanitize_credential('') == ''

def test_sanitize_credential_replacement_char():
    assert sanitize_credential('pass�word') == '<cryptic binary>'

def test_sanitize_credential_non_printable():
    assert sanitize_credential('pass\x00word') == '<cryptic binary>'


# ---------------------------------------------------------------------------
# monitor.sanitize_body
# ---------------------------------------------------------------------------

def test_sanitize_body_preserves_newlines():
    result = sanitize_body('line1\nline2\r\nline3')
    assert 'line1' in result
    assert 'line2' in result

def test_sanitize_body_strips_non_printable():
    result = sanitize_body('hello\x00world')
    assert '\x00' not in result
    assert 'hello' in result
    assert 'world' in result

def test_sanitize_body_truncates():
    result = sanitize_body('a' * 3000, max_len=100)
    assert len(result) == 100

def test_sanitize_body_none():
    assert sanitize_body(None) is None


# ---------------------------------------------------------------------------
# monitor._parse_protocol_entry
# ---------------------------------------------------------------------------

def test_parse_protocol_entry_simple():
    result = _parse_protocol_entry('SSH')
    assert result == ProtocolEntry('SSH', None, ())

def test_parse_protocol_entry_with_port():
    result = _parse_protocol_entry('SMTP:25')
    assert result == ProtocolEntry('SMTP', 25, ())

def test_parse_protocol_entry_unknown_proto():
    assert _parse_protocol_entry('BADPROTO') is None

def test_parse_protocol_entry_bad_port():
    assert _parse_protocol_entry('SSH:notaport') is None

def test_parse_protocol_entry_empty():
    assert _parse_protocol_entry('') is None


# ---------------------------------------------------------------------------
# sip_b2bua helpers
# ---------------------------------------------------------------------------

def test_sip_b2bua_parse_sdp_audio():
    sdp = (
        'v=0\r\n'
        'o=- 1 1 IN IP4 203.0.113.10\r\n'
        's=test\r\n'
        'c=IN IP4 203.0.113.10\r\n'
        't=0 0\r\n'
        'm=audio 49170 RTP/AVP 0 8\r\n'
    )
    media = sip_b2bua.parse_sdp(sdp)
    assert media['connection_ip'] == '203.0.113.10'
    assert media['audio_port'] == 49170
    assert media['payloads'] == ['0', '8']


def test_sip_b2bua_build_sdp_audio():
    sdp = sip_b2bua.build_sdp('198.51.100.5', 30000, ['0', '101'])
    assert 'c=IN IP4 198.51.100.5' in sdp
    assert 'm=audio 30000 RTP/AVP 0' in sdp
    assert '101' not in sdp
    assert 'a=rtpmap:0 PCMU/8000' in sdp
    assert 'a=rtpmap:8 PCMA/8000' not in sdp


def test_sip_b2bua_should_bridge_policy(monkeypatch):
    monkeypatch.setenv('PBX_HOST', '127.0.0.1')
    monkeypatch.setenv('PBX_DIAL_POLICY', 'US,+4420')
    assert sip_b2bua.should_bridge('+12025550123', 'US') is True
    assert sip_b2bua.should_bridge('+442071234567', 'GB') is True
    assert sip_b2bua.should_bridge('+33123456789', 'FR') is False


def test_sip_b2bua_disabled_without_host(monkeypatch):
    monkeypatch.delenv('PBX_HOST', raising=False)
    monkeypatch.setenv('PBX_DIAL_POLICY', 'all')
    assert sip_b2bua.enabled() is False
    assert sip_b2bua.should_bridge('+12025550123', 'US') is False


def test_sip_dial_cache_seed_from_db(tmp_path):
    db_path = tmp_path / 'knock_knock.db'
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE dial_intel (
               number TEXT PRIMARY KEY,
               hits INTEGER,
               first_seen DATETIME,
               last_seen DATETIME,
               country TEXT,
               country_name TEXT,
               lat REAL,
               lng REAL
           )"""
    )
    conn.executemany(
        "INSERT INTO dial_intel VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ('+15052954065', 3, '2026-06-09 19:45:23', '2026-06-09 20:13:42', 'US', 'Albuquerque, NM, United States', 35.0841034, -106.650985),
            ('+615052954065', 1, '2026-06-09 20:07:23', '2026-06-09 20:07:23', 'XX', 'International Network', None, None),
        ],
    )
    conn.commit()
    conn.close()

    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = []
    assert sip_honeypot._seed_dial_cache_from_db(str(db_path)) == 1
    assert sip_honeypot.parse_dial_country('900615052954065')[:3] == (
        'US',
        'Albuquerque, NM, United States',
        '+15052954065',
    )


def test_sip_dial_cache_seed_prefers_higher_hit_suffix_conflict(tmp_path):
    db_path = tmp_path / 'knock_knock.db'
    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE dial_intel (
               number TEXT PRIMARY KEY,
               hits INTEGER,
               first_seen DATETIME,
               last_seen DATETIME,
               country TEXT,
               country_name TEXT,
               lat REAL,
               lng REAL
           )"""
    )
    conn.executemany(
        "INSERT INTO dial_intel VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ('+2092977081', 4, '2026-06-02 09:22:36', '2026-06-09 21:00:00', 'EG', 'Egypt', None, None),
            ('+12092977081', 18199, '2026-04-21 17:25:50', '2026-06-09 15:47:08', 'US', 'California, United States', None, None),
        ],
    )
    conn.commit()
    conn.close()

    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = []
    assert sip_honeypot._seed_dial_cache_from_db(str(db_path)) == 1
    with sip_honeypot._dial_cache_lock:
        assert sip_honeypot._dial_cache[0][:3] == ('12092977081', 'US', 'California, United States')
    assert sip_honeypot.parse_dial_country('800112092977081')[:3] == (
        'US',
        'California, United States',
        '+12092977081',
    )


def test_sip_dial_cache_matches_nanp_national_alias():
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [
            ('12092977081', 'US', 'California, United States', None, None)
        ]
    assert sip_honeypot.parse_dial_country('2092977081')[:3] == (
        'US',
        'California, United States',
        '+12092977081',
    )
