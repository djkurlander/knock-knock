"""
Unit tests for pure helper functions.

No network connections, Redis, SQLite, or subprocess spawning — these
functions are tested in isolation and cannot affect the DB or UI.
"""
import os
import sqlite3
import sys
import time

import pytest

# Make repo root and honeypots/ importable
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'honeypots'))

from common import normalize_ip, extract_addr, smtp_tls_cert_subject
from ip_ban import fmt_ban_until
from ssh_honeypot_asyncssh import _clamp_delay_bounds
import sip_honeypot
import monitor
import protocols.sip as sip_protocol
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


def test_sip_invite_captures_from_user(monkeypatch):
    emitted = []

    def fake_emit_knock(client_ip, extra=None, dedup_key=None):
        emitted.append((client_ip, extra or {}, dedup_key))

    monkeypatch.setattr(sip_honeypot, 'emit_knock', fake_emit_knock)
    req = sip_honeypot.parse_sip_message(
        (
            'INVITE sip:12025550123@198.51.100.10 SIP/2.0\r\n'
            'Via: SIP/2.0/UDP 203.0.113.20:5060;branch=z9hG4bKtest\r\n'
            'From: "Guido" <sip:guido@203.0.113.20>;tag=abc\r\n'
            'To: <sip:12025550123@198.51.100.10>\r\n'
            'Call-ID: from-user-test\r\n'
            'CSeq: 1 INVITE\r\n'
            'Content-Length: 0\r\n'
            '\r\n'
        ).encode()
    )

    assert sip_honeypot.process_sip_request(req, '203.0.113.20')[0] == 'INVITE_FAKE'
    assert emitted
    assert emitted[0][1]['sip_from_user'] == 'guido'


def test_sip_after_save_uses_from_user_as_caller():
    package = {}
    sip_protocol.after_save({'sip_from_user': 'guido', 'sip_uri_user': '12025550123'}, package, {})
    assert package['sip_caller'] == 'guido'


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


def test_sip_dial_full_e164_beats_national_alias():
    """A full cached E.164 present as a suffix of the dialed digits beats a national-alias
    (CC-stripped) match of a *different* cached number — order-independent. India's national
    number ('4570209303') is byte-identical to Denmark's whole E.164, so once a +91 poison
    entry exists the old first-either match resolved '00'+Denmark to India by cache order;
    the full-beats-alias precedence always returns Denmark."""
    for order in (
        [('914570209303', 'IN', 'India', None, None), ('4570209303', 'DK', 'Denmark', None, None)],
        [('4570209303', 'DK', 'Denmark', None, None), ('914570209303', 'IN', 'India', None, None)],
    ):
        with sip_honeypot._dial_cache_lock:
            sip_honeypot._dial_cache[:] = list(order)
        for ds in ('004570209303', '9004570209303', '0004570209303'):
            iso, _, e164, *_ = sip_honeypot.parse_dial_country(ds)
            assert (iso, e164) == ('DK', '+4570209303'), (order, ds)


def test_sip_dial_shortest_full_suffix_wins():
    """When the dialed digits contain both a longer nested full E.164 (a dial-out-prefix
    artifact) and the shorter real base, the shorter base wins."""
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [
            ('915154890969', 'IN', 'India', None, None),      # the 9+US artifact (longer)
            ('15154890969', 'US', 'Iowa', None, None),        # the real base (shorter)
        ]
    iso, _, e164, *_ = sip_honeypot.parse_dial_country('00915154890969')
    assert (iso, e164) == ('US', '+15154890969')


def test_sip_dial_dual_cc_twin_resolves_dialed_cc():
    """+970/+972 (Palestine/Israel) share a national number; each dialed full form resolves
    to the country code actually dialed, not a cache-order guess (both are legit, not merged)."""
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [
            ('970592698190', 'PS', 'West Bank', None, None),
            ('972592698190', 'IL', 'Israel', None, None),
        ]
    assert sip_honeypot.parse_dial_country('972592698190')[0] == 'IL'
    assert sip_honeypot.parse_dial_country('00970592698190')[0] == 'PS'


def test_sip_dial_national_alias_fallback(monkeypatch):
    """The national-alias fallback still catches CC-less trunk-prefixed dials that the greedy
    branches can't ('9'+national) — regression guard for keeping the alias as the fallback."""
    monkeypatch.setattr(sip_honeypot, 'geocode_description', lambda *a, **k: (None, None))
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [
            ('12092977081', 'US', 'California', None, None),
            ('78123746728', 'RU', 'St Petersburg', None, None),
        ]
    assert sip_honeypot.parse_dial_country('92092977081')[0] == 'US'
    assert sip_honeypot.parse_dial_country('988123746728')[0] == 'RU'


def test_sip_dial_explicit_e164_beats_poisoned_cache(monkeypatch):
    """An explicit valid '+'E.164 resolves DIRECTLY (bypassing the suffix cache), so a
    poisoned shorter suffix entry can't shadow it. (Originally observed 2026-04-28:
    '6508601846' mis-stripped to +508601846. The old shorter-suffix eviction that 'repaired'
    the poison was removed — it evicted real bases 7× vs helped 1× over full history, and the
    is_valid parser no longer creates such poison-strips. The explicit-E.164 guarantee below
    is what actually protects the real number.)"""
    monkeypatch.setattr(sip_honeypot, 'geocode_description', lambda *a, **k: (None, None))
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [('508601846', 'PM', 'Saint Pierre And Miquelon', None, None)]
    iso, _, e164, _, _ = sip_honeypot.parse_dial_country('+16508601846')
    assert (iso, e164) == ('US', '+16508601846')           # explicit form is never shadowed


def test_e164_subsumes_cached():
    """A longer valid E.164 that is (dial-out prefix + a cached base) is flagged as
    subsuming, so auto-profiling skips it and we never ring the innocent third party
    whose number is just the tail. Same-length dual-CC twins are NOT subsumed."""
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [
            ('15154890969', 'US', 'Iowa', None, None),
            ('447723178236', 'GB', 'United Kingdom', None, None),
            ('972567004550', 'IL', 'Israel', None, None),
        ]
    assert sip_honeypot._e164_subsumes_cached('+915154890969') is True    # 9 + US base
    assert sip_honeypot._e164_subsumes_cached('+115154890969') is True    # 1 + US base
    assert sip_honeypot._e164_subsumes_cached('+15154890969') is False    # the base itself
    assert sip_honeypot._e164_subsumes_cached('+447723178236') is False   # cached, no shorter base
    assert sip_honeypot._e164_subsumes_cached('+970567004550') is False   # dual-CC twin (same length)
    assert sip_honeypot._e164_subsumes_cached('+13125550123') is False    # unrelated


def test_dial_cache_keeps_shorter_base_against_prefix_twin(monkeypatch):
    """A real base must survive when a longer explicit prefix-twin arrives — the eviction
    no longer removes shorter proper-suffix entries, so 9+<US number> can't evict the base."""
    monkeypatch.setattr(sip_honeypot, 'geocode_description', lambda *a, **k: (None, None))
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = []
    sip_honeypot.parse_dial_country('+15154890969')        # establish the real US base
    sip_honeypot.parse_dial_country('+915154890969')       # the 9+ artifact (explicit +91)
    with sip_honeypot._dial_cache_lock:
        cached = [d for d, *_ in sip_honeypot._dial_cache]
    assert '15154890969' in cached                         # base preserved


def test_sip_dial_bare_nanp_ten_digit(monkeypatch):
    """A bare 10-digit NANP dial ('6508601846') must resolve as +1..., not have its
    first digit stripped into an exotic country code."""
    monkeypatch.setattr(sip_honeypot, 'geocode_description', lambda *a, **k: (None, None))
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = []
    iso, _, e164, _, _ = sip_honeypot.parse_dial_country('6508601846')
    assert (iso, e164) == ('US', '+16508601846')


def test_sip_dial_cache_suffix_beats_exotic_cc_parse():
    """Observed misparses where <PBX digit> + <known number> also happens to parse as
    a valid foreign number: 9+19197508336 → Indian mobile, 8+2022234942 → Seoul (after
    KR national-prefix stripping), 9+7787603331 → Nepal. Cache history must win."""
    cases = [
        (('19197508336', 'US', 'North Carolina, United States'), '919197508336'),
        (('12022234942', 'US', 'Washington D.C., United States'), '82022234942'),
        (('17787603331', 'CA', 'British Columbia, Canada'), '97787603331'),
    ]
    for (digits, iso, name), dial in cases:
        with sip_honeypot._dial_cache_lock:
            sip_honeypot._dial_cache[:] = [(digits, iso, name, None, None)]
        assert sip_honeypot.parse_dial_country(dial)[:3] == (iso, name, f'+{digits}'), dial


def test_sip_dial_cache_national_alias_with_trunk_prefix():
    """Observed 2026-07-02: '988123746728' = 9 (PBX) + 8 (RU trunk) + 812 374 6728,
    dialed 16s after +78123746728 — must match the cached RU number, not Iran."""
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [('78123746728', 'RU', 'St Petersburg, Russia', None, None)]
    assert sip_honeypot.parse_dial_country('988123746728')[:3] == (
        'RU', 'St Petersburg, Russia', '+78123746728')


def test_sip_dial_cache_covers_009_intl_prefix():
    """Observed 2026-06-27: '0093545395213' = 009 (intl access code) + the Iceland
    beacon; a cold-cache parse reads it as 00 + 93... (Afghanistan). Warm history
    must win via the plain suffix match."""
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = [('3545395213', 'IS', 'Reykjavík, Iceland', None, None)]
    assert sip_honeypot.parse_dial_country('0093545395213')[:3] == (
        'IS', 'Reykjavík, Iceland', '+3545395213')


def test_sip_dial_intl_prefix_requires_valid_number(monkeypatch):
    """Observed 2026-06-25: '003116193830436' was accepted as possible-but-invalid
    +31 1619 383 0436 (NL). Requiring validity lets the strip loop find the real
    +1 619 383 0436 dialed three minutes earlier."""
    monkeypatch.setattr(sip_honeypot, 'geocode_description', lambda *a, **k: (None, None))
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = []
    iso, _, e164, _, _ = sip_honeypot.parse_dial_country('003116193830436')
    assert (iso, e164) == ('US', '+16193830436')


def test_sip_dial_junk_probes_rejected():
    """Prefix-permutation probes around invalid cores (1144199199, 1-550-526-7671)
    must not resolve at all now that is_possible_number is no longer accepted."""
    with sip_honeypot._dial_cache_lock:
        sip_honeypot._dial_cache[:] = []
    for dial in ('01144199199', '1144199199', '0015505267671', '915505267671'):
        assert sip_honeypot.parse_dial_country(dial) == (None, None, None, None, None), dial


