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
