"""Self-identity redaction — replace this server's own IP/host/domain identifiers with
stable ``<target-ip>`` / ``<target-host>`` / ``<target-domain>`` markers.

Standalone (stdlib only: os/re/socket/subprocess) so lightweight tools — the SMTP body
backfill, ``updatedb.py`` — can reuse the *exact* redaction the live monitor applies,
including the runtime-*discovered* identifiers (outbound IP, ``getaddrinfo``, ``hostname -I``,
PTR hosts, derived domains), not just ``.env`` values, without importing the full monitor
runtime (geoip, redis, protocol modules, policy/hook building).

Discovery is expensive (DNS/PTR/socket), so callers build the pattern list ONCE
(``build_self_redaction_patterns()``) and reuse it; ``apply_redaction`` is a cheap regex pass.

The markers are stable and each corresponds to a known identifier, so a body could in
principle be restored per-knock by a future relay — no restore path exists here; this module
only replaces. Applying a fleet identifier that does not occur in a body is a harmless no-op,
so ``build_patterns_from_literals`` can union a whole fleet's identifiers.
"""
import os
import re
import socket
import subprocess


def _registrable_domain(host):
    host = (host or '').strip().lower().rstrip('.')
    if not host or '.' not in host:
        return None
    labels = [part for part in host.split('.') if part]
    if len(labels) < 2:
        return None
    # Heuristic for common ccTLD second-level patterns (e.g. example.co.uk).
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac'}:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _is_non_routable_ipv4(ip):
    """True for an IPv4 loopback / RFC1918 / link-local / unspecified address — never a
    self-reference. False for public IPv4, and for anything that isn't a plain IPv4 (IPv6,
    etc.), which passes through unfiltered."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b, c, d = (int(p) for p in parts)
    except ValueError:
        return False
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        return False
    return (a in (0, 127) or a == 10 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or (a == 169 and b == 254))


def discover_self_identifiers():
    """Return (ips, hosts, host_suffixes) for THIS machine — env ``REDACT_SELF_*`` /
    ``DEFAULT_HOSTNAME`` inputs plus runtime discovery (public outbound/bound IPv4s, their
    reverse-DNS PTR aliases, and registrable domains derived from those). The *internal* local
    hostname (gethostname/getfqdn) and non-routable IPs are deliberately excluded."""
    ips = set()
    hosts = set()
    host_suffixes = set()

    # Explicit operator-provided redaction inputs.
    explicit_ips = set()
    for v in os.environ.get('REDACT_SELF_IPS', '').split(','):
        v = v.strip()
        if v:
            ips.add(v)
            explicit_ips.add(v)
    for v in os.environ.get('REDACT_SELF_HOSTS', '').split(','):
        v = v.strip().lower()
        if v:
            hosts.add(v)
    for key in ('REDACT_SELF_DOMAINS', 'REDACT_SELF_HOST_SUFFIXES'):
        for v in os.environ.get(key, '').split(','):
            v = v.strip().lower().lstrip('.')
            if v:
                host_suffixes.add(v)
    # The canonical advertised hostname (DEFAULT_HOSTNAME) — what the protocol banners present
    # and bots reflect back — is a self-identifier too; its registrable domain is derived below.
    dh = os.environ.get('DEFAULT_HOSTNAME', '').strip().lower()
    if dh:
        hosts.add(dh)

    # The local hostname (gethostname/getfqdn) is deliberately NOT added: it's an *internal*
    # name no honeypot advertises, so it never lands in captured data, and a short one (e.g.
    # 'la1') would substring-match unrelated text ('formula1'). The advertised name comes from
    # the reverse-DNS PTR of the public IP (below) + REDACT_SELF_* / DEFAULT_HOSTNAME.

    # Auto-discover primary outbound IPv4 used by this host.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip:
            ips.add(ip)
    except Exception:
        pass

    # Auto-discover IPv4s bound/resolved to this hostname.
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
            if family == socket.AF_INET and sockaddr and sockaddr[0]:
                ips.add(sockaddr[0])
    except Exception:
        pass
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(socket.getfqdn(), None):
            if family == socket.AF_INET and sockaddr and sockaddr[0]:
                ips.add(sockaddr[0])
    except Exception:
        pass
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, stderr=subprocess.DEVNULL).strip()
        for tok in out.split():
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", tok):
                ips.add(tok)
    except Exception:
        pass

    # Drop auto-discovered non-routable IPv4 (loopback / RFC1918 / link-local / docker bridge) —
    # never a self-reference. Explicit REDACT_SELF_IPS are kept even if private.
    ips = {ip for ip in ips if ip in explicit_ips or not _is_non_routable_ipv4(ip)}

    # Reverse lookup discovered IPs for host aliases.
    for ip in list(ips):
        try:
            ptr = socket.gethostbyaddr(ip)[0].strip().lower()
            if ptr:
                hosts.add(ptr)
        except Exception:
            pass
    hosts.discard('localhost')

    # Derive registrable domains from discovered hostnames/PTRs by default.
    for host in list(hosts):
        domain = _registrable_domain(host)
        if domain:
            host_suffixes.add(domain)

    return ips, hosts, host_suffixes


def _patterns_from(ips, hosts, host_suffixes):
    pats = []
    # Hostnames first, then domains, then IPs to avoid partial overlap artifacts.
    for host in sorted(hosts, key=len, reverse=True):
        pats.append((re.compile(re.escape(host), re.IGNORECASE), "<target-host>"))
    for suffix in sorted(host_suffixes, key=len, reverse=True):
        pats.append((
            re.compile(rf"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]+\.)*{re.escape(suffix)}(?![A-Za-z0-9_-])", re.IGNORECASE),
            "<target-domain>",
        ))
    # Longest-first replacement avoids partial overlap artifacts.
    for ip in sorted(ips, key=len, reverse=True):
        pats.append((re.compile(re.escape(ip)), "<target-ip>"))
        # Common dash-notation seen in hostnames (e.g. 1-2-3-4.example.tld).
        dashed = ip.replace('.', '-')
        if dashed != ip:
            pats.append((re.compile(re.escape(dashed), re.IGNORECASE), "<target-ip>"))
    return pats


def build_self_redaction_patterns():
    """Redaction patterns for THIS machine (env + runtime discovery). Expensive — call once."""
    return _patterns_from(*discover_self_identifiers())


def build_patterns_from_literals(ips=(), hosts=(), domains=()):
    """Redaction patterns from explicit identifier lists (no discovery) — used by the
    aggregator fleet backfill, which must redact *other* servers' identifiers it cannot
    discover locally. Registrable-domain suffixes are derived from the given hosts too."""
    ip_set = {x.strip() for x in ips if x and x.strip()}
    host_set = {x.strip().lower() for x in hosts if x and x.strip()}
    suffixes = {x.strip().lower().lstrip('.') for x in domains if x and x.strip()}
    for h in list(host_set):
        d = _registrable_domain(h)
        if d:
            suffixes.add(d)
    return _patterns_from(ip_set, host_set, suffixes)


def apply_redaction(s, patterns):
    """Apply a pattern list (from either builder) to a string. Cheap — safe per-call."""
    if not s:
        return s
    for pat, replacement in patterns:
        s = pat.sub(replacement, s)
    return s
