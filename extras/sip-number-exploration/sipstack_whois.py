#!/usr/bin/env python3
"""Minimal client for the SIPSTACK WHOIS phone-number lookup API.

The public site https://whois.sipstack.com is a client-side app that calls a
JSON endpoint:

    GET https://api-whois.sipstack.com/v1/whois/lookup/<11-digit-number>

It returns line type (VoIP / Wireline / Wireless), carrier of record, rate
center, and a community spam score, sourced from LERG / ported-number data.
This module wraps that endpoint with stdlib only (no third-party deps) so the
other tools in this directory can share one rate-limited, normalized client.

Used by the dial-target line-type investigation; see
../notes/sip-nanp-line-types-whois.md.

CLI:
    python sipstack_whois.py +12092977081
    python sipstack_whois.py 12092977081 18005555111      # several at once

Library:
    from sipstack_whois import lookup
    rec = lookup("+12092977081")   # -> dict (see normalize())

Notes:
  - Unauthenticated; this is the same request an anonymous web visitor makes.
  - Be polite: lookups are serial with a default sleep between calls. The data
    is attacker-supplied (honeypot dial targets) — it is queried, never executed.
"""
import json
import sys
import time
import urllib.error
import urllib.request

API = "https://api-whois.sipstack.com/v1/whois/lookup/"
USER_AGENT = "knock-knock-sip-number-exploration/1.0"
DEFAULT_TIMEOUT = 25


def to_e164_digits(number: str) -> str:
    """Strip everything but digits. '+1 (209) 297-7081' -> '12092977081'."""
    return "".join(ch for ch in str(number) if ch.isdigit())


def lookup(number: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Look up one number. Returns a normalized dict; never raises on a clean
    'not found' — sets ``ok=False`` and an ``error`` string instead."""
    did = to_e164_digits(number)
    req = urllib.request.Request(API + did, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return _err(number, did, f"http_{e.code}")
    except (urllib.error.URLError, TimeoutError) as e:
        return _err(number, did, f"neterr_{e}")
    except json.JSONDecodeError:
        return _err(number, did, "bad_json")

    if isinstance(payload, dict) and payload.get("status") == "error":
        return _err(number, did, f"api_{payload.get('code', '?')}")
    return normalize(number, did, payload)


def normalize(number: str, did: str, p: dict) -> dict:
    """Flatten the API JSON into the fields the analysis tools use."""
    tech = p.get("technical") or {}
    geo = p.get("regional") or {}
    prot = p.get("protection") or {}
    return {
        "ok": True,
        "input": number,
        "did": did,
        "type": tech.get("type") or "",          # VoIP / Wireline / Wireless / ""
        "carrier": tech.get("carrier") or "",
        "rate_center": tech.get("rateCenter") or "",
        "lata": tech.get("lata"),
        "city": geo.get("city") or "",
        "region": geo.get("region") or "",
        "cnam": p.get("name") or "",
        "score": prot.get("score") or "",
        "error": "",
    }


def _err(number: str, did: str, msg: str) -> dict:
    return {
        "ok": False, "input": number, "did": did, "type": "", "carrier": "",
        "rate_center": "", "lata": None, "city": "", "region": "", "cnam": "",
        "score": "", "error": msg,
    }


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    for i, num in enumerate(argv):
        if i:
            time.sleep(0.25)
        print(json.dumps(lookup(num), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
