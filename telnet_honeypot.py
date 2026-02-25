#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import redis

_r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

def is_blocked(ip):
    try:
        return _r.sismember("knock:blocked", ip)
    except Exception:
        return False

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

def normalize_ip(ip):
    """Normalize IPv4-mapped IPv6 addresses to plain IPv4."""
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip

def start_honeypot():
    # Dual-stack socket: accepts both IPv4 and IPv6
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 23))
    sock.listen(100)

    print("🚀 Telnet Honeypot Active on Port 23 (IPv4+IPv6). Collecting radiation...", flush=True)

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()
