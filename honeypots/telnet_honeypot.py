#!/usr/bin/env python3
import socket
import threading
import time
import json
import os
import re
from common import PerIpTokenBucket, create_dualstack_tcp_listener, is_blocked, normalize_ip

TNET_DEDUP_WINDOW_SEC = int(os.environ.get('TNET_DEDUP_WINDOW_SEC', '0'))
_throttle = PerIpTokenBucket(os.environ.get('TNET_THROTTLE_PER_SEC', '0'))
_dedup_lock = threading.Lock()
_dedup_seen: dict = {}


# Other-protocol scanners that hit port 23 send a protocol greeting (an HTTP request
# line, SSH/SIP/RTSP banner, or the MGLNDD mass-scan probe) which the raw Telnet reader
# captures as a "credential". Match the structural protocol *token* (not individual scan
# strings) so one pattern covers every method/path/version variant + future ones. None of
# these tokens occur in a real Telnet credential, so false-positive risk is ~nil.
_PROTO_GREETING_RE = re.compile(
    r' HTTP/[0-9]'      # HTTP request line (any method/path/version)
    r'|^SSH-[0-9]'      # SSH version banner
    r'|\bSIP/2\.0\b'    # SIP (e.g. sipvicious OPTIONS sip:nm SIP/2.0)
    r'|\bRTSP/[0-9]'    # RTSP (IoT camera / stream scanners)
    r'|^MGLNDD_',       # MGLNDD mass-scanner connectivity probe
    re.IGNORECASE,
)


def _looks_binary(s):
    """A credential that failed UTF-8 decoding (replacement char) or carries non-printable
    bytes — i.e. the same input that would render as '<cryptic binary>' downstream."""
    return bool(s) and ('�' in s or not s.isprintable())


def _is_noise(user, password):
    """True if this isn't a real Telnet login but non-Telnet traffic on port 23 — binary
    protocol flails (TLS, scanners) or another protocol's greeting (HTTP/SSH/SIP/RTSP/
    MGLNDD). Telnet is a raw line protocol with no command/handshake gate, so it otherwise
    captures such traffic as bogus knocks; the structured protocols (SSH/FTP/RDP/SMB)
    reject it before it becomes a knock, and this gives Telnet the equivalent gate. Blank
    credentials are printable, tokenless, and still emit (a blank password is a real try)."""
    return any(_looks_binary(s) or (s and _PROTO_GREETING_RE.search(s))
               for s in (user, password))


def should_emit(ip, user, password):
    if TNET_DEDUP_WINDOW_SEC <= 0:
        return _throttle.allow(ip)
    key = (ip, user, password)
    now = time.time()
    with _dedup_lock:
        cutoff = now - TNET_DEDUP_WINDOW_SEC
        stale = [k for k, ts in _dedup_seen.items() if ts < cutoff]
        for k in stale:
            _dedup_seen.pop(k, None)
        if key in _dedup_seen:
            return False
        if not _throttle.allow(ip):
            return False
        _dedup_seen[key] = now
        return True

# Telnet protocol constants (RFC 854)
IAC  = 0xFF  # Interpret As Command
WILL = 0xFB  # I will use this option
WONT = 0xFC  # I won't use this option
DO   = 0xFD  # Please use this option
DONT = 0xFE  # Please don't use this option
ECHO = 0x01  # Echo option
SGA  = 0x03  # Suppress Go Ahead
LINEMODE = 0x22  # Line mode option

def recv_line(sock, echo=False, timeout=20):
    """Read one line from a Telnet connection, stripping IAC negotiation sequences."""
    sock.settimeout(timeout)
    buf = b''
    try:
        while True:
            ch = sock.recv(1)
            if not ch:
                break

            b = ch[0]

            # Handle IAC sequences inline
            if b == IAC:
                cmd = sock.recv(1)
                if not cmd:
                    break
                c = cmd[0]
                if c in (WILL, WONT, DO, DONT):
                    sock.recv(1)  # consume the option byte
                # else: 2-byte IAC command, already consumed; just ignore
                continue

            # Line terminators
            if b in (0x0D, 0x0A):  # CR or LF
                if buf:
                    break
                continue  # skip leading blank lines

            if b == 0x00:  # Telnet NUL (sent after CR in some clients)
                continue

            # Backspace / DEL
            if b in (0x08, 0x7F):
                if buf:
                    if echo:
                        sock.sendall(b'\x08 \x08')  # erase character on terminal
                    buf = buf[:-1]
                continue

            buf += ch
            if echo:
                sock.sendall(ch)  # server-side echo (we own ECHO)

    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass

    return buf.decode('utf-8', errors='replace').strip()

def handle_connection(client_sock, client_ip):
    try:
        client_sock.settimeout(20)

        # Negotiate character-at-a-time mode:
        #   WILL ECHO     — server handles echo, client should not local-echo
        #   WILL SGA      — suppress go-ahead (full-duplex)
        #   DONT LINEMODE — disable client line buffering
        client_sock.sendall(bytes([IAC, WILL, ECHO,
                                   IAC, WILL, SGA,
                                   IAC, DONT, LINEMODE]))

        # Realistic Ubuntu login banner
        client_sock.sendall(b"\r\nUbuntu 22.04.4 LTS\r\n\r\nlogin: ")
        username = recv_line(client_sock, echo=True)
        if not username:
            return

        client_sock.sendall(b"\r\nPassword: ")
        password = recv_line(client_sock, echo=False)  # no echo for password

        # Drop non-Telnet traffic (binary flails + other-protocol scanner greetings)
        # before it becomes a knock, matching the structural gating SSH/FTP/RDP/SMB get
        # for free.
        if not _is_noise(username, password) and should_emit(client_ip, username, password):
            print(json.dumps({"type": "KNOCK", "proto": "TNET",
                              "ip": client_ip, "user": username, "pass": password}), flush=True)

        client_sock.sendall(b"\r\nLogin incorrect\r\n\r\n")

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_honeypot(port=23):
    # Dual-stack socket: accepts both IPv4 and IPv6
    sock = create_dualstack_tcp_listener(port, backlog=100)

    print(f"🚀 Telnet Honeypot Active on Port {port} (IPv4+IPv6). Collecting knocks...", flush=True)

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=23)
    args = parser.parse_args()
    start_honeypot(port=args.port)
