"""Public-repo regression: the SIP honeypot must run WITHOUT the private B2BUA engine.

The public repo ships `honeypots/sip_honeypot.py` but deliberately NOT `sip_b2bua.py` /
`sip_dial_profile.py` — those live in a private overlay. `sip_honeypot` guards their import
(`try: import sip_b2bua … except ImportError: HAVE_B2BUA = False`) and every `sip_b2bua.*`
call is gated on `HAVE_B2BUA`, so on a public checkout an INVITE is answered down the local
`INVITE_FAKE` / `404` path with no private call.

This locks that guarantee into CI: without such a test, a future refactor could reintroduce
an ungated `sip_b2bua.*` call and silently break the public build (the same class of bug as a
Dockerfile omitting a runtime module). We run in a **subprocess** because other tests import
the private modules in-process and they can't be cleanly un-imported; a fresh interpreter with
the two modules blocked is the only faithful simulation of a public-only checkout.
"""
import os
import subprocess
import sys
import textwrap

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Runs in a clean interpreter with sip_b2bua / sip_dial_profile made unimportable, then drives
# a real INVITE through the handler and asserts it stays on the local (non-private) path.
_CHILD = textwrap.dedent(
    """
    import importlib.abc
    import os
    import sys

    class _Block(importlib.abc.MetaPathFinder):
        # Simulate the public checkout: the private overlay modules simply aren't there.
        def find_spec(self, name, path, target=None):
            if name in ("sip_b2bua", "sip_dial_profile"):
                raise ModuleNotFoundError(name)
            return None

    sys.meta_path.insert(0, _Block())
    sys.path.insert(0, os.path.join(os.environ["KK_ROOT"], "honeypots"))

    import sip_honeypot as s

    # 1. The import guard degraded gracefully.
    assert s.HAVE_B2BUA is False, "HAVE_B2BUA must be False without the private engine"
    assert s.sip_b2bua is None and s.sip_dial_profile is None

    # 2. A real INVITE is handled locally — no sip_b2bua.* call, no crash.
    invite = (
        "INVITE sip:+18005551212@1.2.3.4 SIP/2.0\\r\\n"
        "Via: SIP/2.0/UDP 9.9.9.9:5060;branch=z9hG4bKpubtest\\r\\n"
        "From: <sip:100@9.9.9.9>;tag=t1\\r\\n"
        "To: <sip:+18005551212@1.2.3.4>\\r\\n"
        "Call-ID: pub-no-b2bua@9.9.9.9\\r\\n"
        "CSeq: 1 INVITE\\r\\n"
        "Contact: <sip:100@9.9.9.9>\\r\\n"
        "Content-Length: 0\\r\\n\\r\\n"
    ).encode()
    req = s.parse_sip_message(invite)
    assert req and req.get("method") == "INVITE", "INVITE did not parse"

    # allow_b2bua=True exercises the branch that WOULD call the private engine if it existed;
    # with HAVE_B2BUA False it must fall through to INVITE_FAKE (answered) or 404 (rejected).
    kind = s.process_sip_request(req, "9.9.9.9", allow_b2bua=True)[0]
    assert kind in ("INVITE_FAKE", 404), f"expected local handling, got {kind!r}"

    print("PUBLIC_NO_B2BUA_OK", kind)
    """
)


def test_sip_honeypot_runs_without_private_b2bua():
    env = dict(os.environ, KK_ROOT=_ROOT)
    env.setdefault("REDIS_HOST", "localhost")
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD],
        capture_output=True,
        text=True,
        env=env,
        cwd=_ROOT,
    )
    assert proc.returncode == 0, (
        "public-only SIP path failed (sip_honeypot needs the private b2bua engine?):\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "PUBLIC_NO_B2BUA_OK" in proc.stdout, proc.stdout
