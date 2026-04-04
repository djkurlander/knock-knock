#!/usr/bin/env python3
import asyncio
import errno
import json
import os
import random
import socket
import shutil

import asyncssh
import asyncssh.rsa

# Remove AsyncSSH-specific @ssh.com host key algorithm variants that
# real OpenSSH never advertises (fingerprinting tell).
asyncssh.rsa.RSAKey.sig_algorithms = (
    b'rsa-sha2-256', b'rsa-sha2-512', b'ssh-rsa'
)

# Keep kex-strict-s-v00@openssh.com (Terrapin countermeasure).  Technically
# added in OpenSSH 9.6, but widely backported to 8.x packages and required
# for correct packet sequencing with modern clients that advertise
# kex-strict-c.  Removing it causes "Bad packet length" corruption.

from common import is_blocked, normalize_ip

_DB_DIR = os.environ.get("DB_DIR", "data")
SSH_HOST_KEY_PATH = os.environ.get(
    "SSH_HOST_KEY_PATH", os.path.join(_DB_DIR, "ssh_host_rsa_key")
)
SSH_ED25519_KEY_PATH = os.environ.get(
    "SSH_ED25519_KEY_PATH", os.path.join(_DB_DIR, "ssh_host_ed25519_key")
)
SSH_LEGACY_HOST_KEY_PATH = "server.key"
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
SSH_PROFILE = os.environ.get("SSH_PROFILE", "openssh_8_9_ubuntu").strip().lower()
SSH_LOGIN_TIMEOUT = float(os.environ.get("SSH_LOGIN_TIMEOUT", "120"))
SSH_MAX_AUTH_ATTEMPTS = int(os.environ.get("SSH_MAX_AUTH_ATTEMPTS", "6"))
SSH_AUTH_DELAY_MS_MIN = int(os.environ.get("SSH_AUTH_DELAY_MS_MIN", "200"))
SSH_AUTH_DELAY_MS_MAX = int(os.environ.get("SSH_AUTH_DELAY_MS_MAX", "600"))

PROFILES = {
    # Modern profile aligned to our current Paramiko banner/fingerprint intent.
    "openssh_8_9_ubuntu": {
        "server_version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.14",
        "kex_algs": [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
        ],
        "encryption_algs": [
            "chacha20-poly1305@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
        ],
        "mac_algs": [
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
        ],
        "compression_algs": ["none", "zlib@openssh.com"],
        "signature_algs": ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"],
    },
    # Optional broader profile that accepts older clients/probes.
    "legacy_compat": {
        "server_version": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
        "kex_algs": [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1",
        ],
        "encryption_algs": [
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-cbc",
            "aes256-cbc",
            "3des-cbc",
        ],
        "mac_algs": [
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1",
            "hmac-md5",
        ],
        "compression_algs": ["none", "zlib@openssh.com"],
        "signature_algs": ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
    },
}


def _parse_csv_env(name):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    vals = [v.strip() for v in raw.split(",")]
    vals = [v for v in vals if v]
    return vals or None


def _clamp_delay_bounds(min_ms, max_ms):
    a = max(0, int(min_ms))
    b = max(0, int(max_ms))
    return (a, b) if a <= b else (b, a)


def _build_profile():
    profile = dict(PROFILES.get(SSH_PROFILE, PROFILES["openssh_8_9_ubuntu"]))
    overrides = {
        "server_version": os.environ.get("SSH_SERVER_VERSION", "").strip() or None,
        "kex_algs": _parse_csv_env("SSH_KEX_ALGS"),
        "encryption_algs": _parse_csv_env("SSH_ENCRYPTION_ALGS"),
        "mac_algs": _parse_csv_env("SSH_MAC_ALGS"),
        "compression_algs": _parse_csv_env("SSH_COMPRESSION_ALGS"),
        "signature_algs": _parse_csv_env("SSH_SIGNATURE_ALGS"),
    }
    for k, v in overrides.items():
        if v:
            profile[k] = v
    return profile


def ensure_host_keys():
    os.makedirs(os.path.dirname(SSH_HOST_KEY_PATH) or ".", exist_ok=True)
    # RSA key (3072-bit to match modern OpenSSH default)
    if not os.path.exists(SSH_HOST_KEY_PATH) and os.path.exists(SSH_LEGACY_HOST_KEY_PATH):
        shutil.copyfile(SSH_LEGACY_HOST_KEY_PATH, SSH_HOST_KEY_PATH)
        os.chmod(SSH_HOST_KEY_PATH, 0o600)
    if os.path.exists(SSH_HOST_KEY_PATH):
        existing = asyncssh.read_private_key(SSH_HOST_KEY_PATH)
        if existing.algorithm == b"ssh-rsa" and existing.pyca_key.key_size < 3072:
            print(f"⚠️ RSA host key is {existing.pyca_key.key_size}-bit, regenerating at 3072-bit", flush=True)
            os.remove(SSH_HOST_KEY_PATH)
    if not os.path.exists(SSH_HOST_KEY_PATH):
        asyncssh.generate_private_key("ssh-rsa", key_size=3072).write_private_key(SSH_HOST_KEY_PATH)
        os.chmod(SSH_HOST_KEY_PATH, 0o600)
    # Ed25519 key
    if not os.path.exists(SSH_ED25519_KEY_PATH):
        ed_key = asyncssh.generate_private_key("ssh-ed25519")
        ed_key.write_private_key(SSH_ED25519_KEY_PATH)
        os.chmod(SSH_ED25519_KEY_PATH, 0o600)


class SSHHoneypotServer(asyncssh.SSHServer):
    def __init__(self, auth_delay_range_ms=(0, 0), max_auth_attempts=6):
        self._client_ip = ""
        self._conn = None
        self._auth_delay_range_ms = auth_delay_range_ms
        self._max_auth_attempts = max_auth_attempts
        self._auth_attempt_count = 0

    def connection_made(self, conn):
        self._conn = conn
        peer = conn.get_extra_info("peername")
        ip = peer[0] if peer else ""
        self._client_ip = normalize_ip(ip) if ip else ""
        if self._client_ip and is_blocked(self._client_ip):
            conn.close()

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return False

    async def validate_password(self, username, password):
        # Optional delay/jitter to reduce robotic timing signatures.
        lo, hi = self._auth_delay_range_ms
        if hi > 0:
            await asyncio.sleep(random.uniform(lo, hi) / 1000.0)
        print(
            json.dumps(
                {
                    "type": "KNOCK",
                    "proto": "SSH",
                    "ip": self._client_ip,
                    "user": username,
                    "pass": password,
                }
            ),
            flush=True,
        )
        self._auth_attempt_count += 1
        if self._auth_attempt_count >= self._max_auth_attempts and self._conn:
            self._conn.close()
        return False

    def connection_lost(self, exc):
        # Keep quiet for normal disconnects.
        pass


async def start_honeypot():
    ensure_host_keys()
    profile = _build_profile()
    delay_bounds = _clamp_delay_bounds(SSH_AUTH_DELAY_MS_MIN, SSH_AUTH_DELAY_MS_MAX)
    server_factory = lambda: SSHHoneypotServer(
        auth_delay_range_ms=delay_bounds,
        max_auth_attempts=SSH_MAX_AUTH_ATTEMPTS,
    )

    # Ed25519 first (preferred by modern OpenSSH), RSA as fallback
    host_keys = [SSH_ED25519_KEY_PATH, SSH_HOST_KEY_PATH]

    listen_kwargs = {
        "port": SSH_PORT,
        "server_factory": server_factory,
        "server_host_keys": host_keys,
        "server_version": profile["server_version"],
        "login_timeout": SSH_LOGIN_TIMEOUT,
        "reuse_address": True,
    }
    for key in (
        "kex_algs",
        "encryption_algs",
        "mac_algs",
        "compression_algs",
        "signature_algs",
    ):
        val = profile.get(key)
        if val:
            listen_kwargs[key] = val

    listeners = []
    bound_hosts = []

    # IPv4 is the priority: retry for up to 10s if port is still held by
    # a previous process (common during restart).
    for attempt in range(10):
        try:
            listener_v4 = await asyncssh.listen(
                host="0.0.0.0",
                family=socket.AF_INET,
                **listen_kwargs,
            )
            listeners.append(listener_v4)
            bound_hosts.append("0.0.0.0")
            break
        except OSError as e:
            if e.errno == errno.EADDRINUSE and attempt < 9:
                await asyncio.sleep(1)
            else:
                print(f"!!! AsyncSSH bind failed host=0.0.0.0 port={SSH_PORT}: [errno {e.errno}] {e}", flush=True)
                raise

    # Bind IPv6 when available; continue in IPv4-only mode if IPv6 bind fails.
    try:
        listener_v6 = await asyncssh.listen(
            host="::",
            family=socket.AF_INET6,
            **listen_kwargs,
        )
        listeners.append(listener_v6)
        bound_hosts.append("::")
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            print(f"⚠️ AsyncSSH IPv6 bind skipped host=:: port={SSH_PORT}: [errno {e.errno}] {e}", flush=True)
        else:
            print(f"⚠️ AsyncSSH IPv6 bind failed host=:: port={SSH_PORT}: [errno {e.errno}] {e}", flush=True)

    print(
        f"🚀 SSH Honeypot (AsyncSSH) Active on Port {SSH_PORT}"
        f" ({' + '.join(bound_hosts)}). Collecting knocks..."
        f" profile={SSH_PROFILE if SSH_PROFILE in PROFILES else 'openssh_8_9_ubuntu'}"
        f" version={profile['server_version']}"
        f" auth_delay_ms={delay_bounds[0]}-{delay_bounds[1]}",
        flush=True,
    )
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start_honeypot())
    except (OSError, asyncssh.Error) as e:
        print(f"!!! AsyncSSH startup error: {e}", flush=True)
