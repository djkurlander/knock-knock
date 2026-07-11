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
from sip_dial_reconcile import same_ip_subset  # noqa: E402


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
