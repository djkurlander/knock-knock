"""Unit tests for the same-IP prefix-twin collapse in sip_dial_reconcile.

A single IP dialing both a number and (dial-out-prefix + that number) is
enumeration, so the longer '+91…'/'+21…' form is an artifact of an unstripped
trunk prefix, not a real foreign number, and collapses to the subset. Same-IP +
suffix is conclusive, so there is no trunk-prefix guard — but legit same-length
dual-CC twins (+970/+972) are never suffixes of each other and stay untouched.
"""
import os
import sys
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "extras"))
from sip_dial_reconcile import same_ip_subset, subsumes_current  # noqa: E402


def _maps(dials):
    """dials: list of (ip, e164) -> (number_ips, ip_digits), as the reconciler builds them."""
    number_ips = defaultdict(set)
    ip_digits = defaultdict(dict)
    for ip, num in dials:
        number_ips[num].add(ip)
        ip_digits[ip][num.lstrip("+")] = num
    return number_ips, ip_digits


def test_collapses_same_ip_prefix_twin():
    # one IP dials both the US number and 9+it (libphonenumber reads the latter as +91 India)
    ni, idg = _maps([("1.1.1.1", "+15154890969"), ("1.1.1.1", "+915154890969")])
    assert same_ip_subset("+915154890969", ni, idg) == "+15154890969"


def test_collapses_two_digit_prefix():
    # +45 Denmark base + "91" prepended -> +914570209303; a 2-digit prefix still collapses
    ni, idg = _maps([("1.1.1.1", "+4570209303"), ("1.1.1.1", "+914570209303")])
    assert same_ip_subset("+914570209303", ni, idg) == "+4570209303"


def test_requires_same_ip():
    # different IPs dialed the artifact vs the base -> no same-IP evidence -> keep as-is
    ni, idg = _maps([("1.1.1.1", "+15154890969"), ("2.2.2.2", "+915154890969")])
    assert same_ip_subset("+915154890969", ni, idg) is None


def test_ignores_same_length_dual_cc_twin():
    # +970 Palestine / +972 Israel: same national number, same length -> not a suffix -> keep both
    ni, idg = _maps([("1.1.1.1", "+970567004550"), ("1.1.1.1", "+972567004550")])
    assert same_ip_subset("+972567004550", ni, idg) is None
    assert same_ip_subset("+970567004550", ni, idg) is None


def test_no_twin_returns_none():
    # a plain number with no shorter same-IP suffix stays canonical
    ni, idg = _maps([("1.1.1.1", "+15154890969")])
    assert same_ip_subset("+15154890969", ni, idg) is None


# --- subsumes_current: the explicit-branch guard -------------------------------
# Bots that only ever dial the prefixed form leave no same-IP twin, but the live
# parser already resolved cur to the real shorter number. An explicit '+91…' must
# not override that valid suffix reading (else the reconciler mints a bogus +91 row).

def test_subsumes_current_keeps_valid_suffix_reading():
    # cur = real US number; explicit form is 9+it read as +91 India -> keep cur
    assert subsumes_current("+919197508320", "+19197508320") is True
    assert subsumes_current("+914570209303", "+4570209303") is True   # 2-digit prefix
    assert subsumes_current("+218644100886", "+18644100886") is True  # "2" prefix


def test_subsumes_current_false_when_not_a_suffix():
    # +970/+972 dual-CC twins are the same length -> neither subsumes the other
    assert subsumes_current("+972567004550", "+970567004550") is False
    # unrelated cur is not a suffix
    assert subsumes_current("+919197508320", "+15154890969") is False


def test_subsumes_current_requires_valid_and_proper_shorter():
    assert subsumes_current("+919197508320", None) is False          # unresolved cur
    assert subsumes_current("+919197508320", "+999999999999") is False  # cur not a valid number
    assert subsumes_current("+15154890969", "+15154890969") is False    # equal, not proper suffix


def test_subsumes_current_ignores_short_suffix():
    # a <9-digit tail is coincidence-prone; guard requires >=9 digits
    assert subsumes_current("+12345678", "+2345678") is False
