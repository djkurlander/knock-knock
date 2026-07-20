"""
Unit tests for DEFAULT_HOSTNAME / per-protocol advertised-host resolution and its redaction
hook. The load-bearing guarantee: with **no host env vars set**, the honeypot defaults are
byte-identical to before (SMTP reverse-DNS, SMB WIN-SRV#### fake).
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, 'honeypots'))

import common
import self_redaction


# --------------------------------------------------------------- advertised_host precedence

def test_advertised_host_precedence(monkeypatch):
    for k in ('SMTP_HOSTNAME', 'DEFAULT_HOSTNAME'):
        monkeypatch.delenv(k, raising=False)
    assert common.advertised_host('SMTP_HOSTNAME') == ''                 # nothing set → fallback
    monkeypatch.setenv('DEFAULT_HOSTNAME', 'mail.corp.example')
    assert common.advertised_host('SMTP_HOSTNAME') == 'mail.corp.example'  # DEFAULT fills the middle
    monkeypatch.setenv('SMTP_HOSTNAME', 'mx1.corp.example')
    assert common.advertised_host('SMTP_HOSTNAME') == 'mx1.corp.example'   # explicit wins
    monkeypatch.setenv('SMTP_HOSTNAME', 'auto')
    assert common.advertised_host('SMTP_HOSTNAME') == ''                   # 'auto' forces fallback


def test_netbios_name():
    assert common.netbios_name('mail.corp.example') == 'MAIL'
    assert common.netbios_name('fileserver01') == 'FILESERVER01'
    long = common.netbios_name('averylonghostname.example')
    assert long == 'AVERYLONGHOSTNA' and len(long) == 15


# --------------------------------------------------------------- backward-compat: unset == today

def test_smb_win_srv_fake_survives_netbios_render():
    # SMB unset → netbios_name(_default_smb_server_name()); the fake is always 'WIN-SRV####'
    # (≤15, upper, dot-less), so netbios_name() is a no-op → byte-identical to the old default.
    for suffix in (0, 1, 42, 1012, 9999):
        name = f'WIN-SRV{suffix:04d}'
        assert common.netbios_name(name) == name


def test_smb_server_name_logic(monkeypatch):
    fake = 'WIN-SRV1012'
    expr = lambda: common.netbios_name(common.advertised_host('SMB_SERVER_NAME') or fake)  # noqa: E731
    for k in ('SMB_SERVER_NAME', 'DEFAULT_HOSTNAME'):
        monkeypatch.delenv(k, raising=False)
    assert expr() == fake                                    # unset → fake (unchanged)
    monkeypatch.setenv('DEFAULT_HOSTNAME', 'mail.corp.example')
    assert expr() == 'MAIL'                                   # DEFAULT_HOSTNAME → coherent short name
    monkeypatch.setenv('SMB_SERVER_NAME', 'auto')
    assert expr() == fake                                    # 'auto' → fake even with DEFAULT set
    monkeypatch.setenv('SMB_SERVER_NAME', 'FS01')
    assert expr() == 'FS01'                                   # explicit


def test_smtp_hostname_precedence_and_fallback(monkeypatch):
    monkeypatch.setattr(common, '_smtp_reverse_dns', lambda: 'REVDNS')   # no network
    for k in ('SMTP_HOSTNAME', 'DEFAULT_HOSTNAME'):
        monkeypatch.delenv(k, raising=False)
    assert common.get_smtp_hostname() == 'REVDNS'            # unset → reverse DNS (unchanged)
    monkeypatch.setenv('DEFAULT_HOSTNAME', 'srv.corp')
    assert common.get_smtp_hostname() == 'srv.corp'
    monkeypatch.setenv('SMTP_HOSTNAME', 'banner.corp')
    assert common.get_smtp_hostname() == 'banner.corp'
    monkeypatch.setenv('SMTP_HOSTNAME', 'auto')
    assert common.get_smtp_hostname() == 'REVDNS'            # 'auto' → reverse DNS


# --------------------------------------------------------------- redaction integration

def test_discover_includes_default_hostname(monkeypatch):
    monkeypatch.setenv('DEFAULT_HOSTNAME', 'mail.testcorp.example')
    _ips, hosts, suffixes = self_redaction.discover_self_identifiers()
    assert 'mail.testcorp.example' in hosts
    assert 'testcorp.example' in suffixes                     # registrable domain derived


def test_discover_excludes_default_hostname_when_unset(monkeypatch):
    monkeypatch.delenv('DEFAULT_HOSTNAME', raising=False)
    _ips, hosts, _suffixes = self_redaction.discover_self_identifiers()
    assert 'mail.testcorp.example' not in hosts


# --------------------------------------------------------------- discovery hygiene

def test_is_non_routable_ipv4():
    nr = self_redaction._is_non_routable_ipv4
    for ip in ('127.0.0.1', '127.0.1.1', '10.1.2.3', '172.16.0.1', '172.17.0.1',
               '172.31.255.255', '192.168.1.1', '169.254.1.1', '0.0.0.0'):
        assert nr(ip) is True, ip
    for ip in ('8.8.8.8', '107.173.37.88', '172.32.0.1', '172.15.0.1', '203.0.113.5'):
        assert nr(ip) is False, ip
    for junk in ('not-an-ip', '::1', '1.2.3', '1.2.3.4.5', '1.2.3.999'):
        assert nr(junk) is False                              # not a plain IPv4 → passthrough


def test_internal_hostname_excluded_from_identity(monkeypatch):
    # gethostname/getfqdn are internal names no honeypot advertises → never in the identity
    monkeypatch.setattr(self_redaction.socket, 'gethostname', lambda: 'internalbox-xyz')
    monkeypatch.setattr(self_redaction.socket, 'getfqdn', lambda: 'internalbox-xyz.local')
    monkeypatch.delenv('DEFAULT_HOSTNAME', raising=False)
    _ips, hosts, _suf = self_redaction.discover_self_identifiers()
    assert 'internalbox-xyz' not in hosts
    assert 'internalbox-xyz.local' not in hosts
    assert 'localhost' not in hosts


def test_explicit_private_ip_kept_nonroutable_discovered_dropped(monkeypatch):
    monkeypatch.setenv('REDACT_SELF_IPS', '192.168.5.5')      # explicit private → kept
    ips, _hosts, _suf = self_redaction.discover_self_identifiers()
    assert '192.168.5.5' in ips
    assert not any(ip.startswith('127.') for ip in ips)      # auto-discovered loopback dropped
