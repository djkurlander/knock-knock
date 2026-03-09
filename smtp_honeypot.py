#!/root/knock-knock/.venv/bin/python
import socket
import threading
import json
import os
import base64
import random
import string
import time
import uuid
import ssl
import redis

_r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

def is_blocked(ip):
    try:
        return _r.sismember("knock:blocked", ip)
    except Exception:
        return False

def _get_smtp_hostname():
    """Resolve our own reverse DNS for a realistic SMTP banner; fall back to IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip
    except Exception:
        return 'localhost'

_SMTP_HOSTNAME = _get_smtp_hostname()

def build_ehlo_response(hostname, caps):
    if not caps:
        return f"250 {hostname}\r\n".encode()
    lines = [f"250-{hostname}"]
    for cap in caps[:-1]:
        lines.append(f"250-{cap}")
    lines.append(f"250 {caps[-1]}")
    return ("\r\n".join(lines) + "\r\n").encode()

SMTP_FINGERPRINT = os.environ.get('SMTP_FINGERPRINT', 'postfix').strip().lower()
SMTP_FINGERPRINTS = {
    'postfix': {
        'banner': 'ESMTP Postfix',
        'ehlo_plain': [
            'PIPELINING', 'SIZE 10240000', 'VRFY', 'ETRN',
            'STARTTLS', 'AUTH LOGIN PLAIN', 'AUTH=LOGIN PLAIN',
            'ENHANCEDSTATUSCODES', '8BITMIME', 'DSN',
        ],
        'ehlo_tls': [
            'PIPELINING', 'SIZE 10240000', 'VRFY', 'ETRN',
            'AUTH LOGIN PLAIN', 'AUTH=LOGIN PLAIN',
            'ENHANCEDSTATUSCODES', '8BITMIME', 'DSN',
        ],
    },
    'exim': {
        'banner': 'ESMTP Exim 4.97',
        'ehlo_plain': [
            'PIPELINING', 'SIZE 52428800', '8BITMIME',
            'STARTTLS', 'AUTH PLAIN LOGIN',
        ],
        'ehlo_tls': [
            'PIPELINING', 'SIZE 52428800', '8BITMIME',
            'AUTH PLAIN LOGIN',
        ],
    },
    'exchange': {
        'banner': 'Microsoft ESMTP MAIL Service ready',
        'ehlo_plain': [
            'SIZE 37748736', 'PIPELINING', 'DSN',
            'ENHANCEDSTATUSCODES', 'STARTTLS', 'AUTH LOGIN',
        ],
        'ehlo_tls': [
            'SIZE 37748736', 'PIPELINING', 'DSN',
            'ENHANCEDSTATUSCODES', 'AUTH LOGIN',
        ],
    },
}
if SMTP_FINGERPRINT not in SMTP_FINGERPRINTS:
    SMTP_FINGERPRINT = 'postfix'
_FP = SMTP_FINGERPRINTS[SMTP_FINGERPRINT]
_BANNER = f"220 {_SMTP_HOSTNAME} {_FP['banner']}\r\n".encode()
_EHLO_RESP = build_ehlo_response(_SMTP_HOSTNAME, _FP['ehlo_plain'])
_EHLO_RESP_TLS = build_ehlo_response(_SMTP_HOSTNAME, _FP['ehlo_tls'])

MAX_MESSAGES_PER_SESSION = 10
SMTP587_REQUIRE_AUTH = os.environ.get('SMTP587_REQUIRE_AUTH', '0').lower() in ('1', 'true', 'yes', 'on')
SMTP_TRACE_ENABLED = os.environ.get('SMTP_TRACE', '1').lower() not in ('0', 'false', 'no')
SMTP_TRACE_IP = os.environ.get('SMTP_TRACE_IP', '').strip()
SMTP_TLS_CERT_PATH = os.environ.get('SMTP_TLS_CERT_PATH', 'data/rdp.crt')
SMTP_TLS_KEY_PATH = os.environ.get('SMTP_TLS_KEY_PATH', 'data/rdp.key')

def queue_ok_reply(queue_id):
    if SMTP_FINGERPRINT == 'exim':
        return f"250 OK id={queue_id}\r\n"
    if SMTP_FINGERPRINT == 'exchange':
        internal_id = random.randint(100000, 999999)
        return f"250 2.6.0 <{queue_id}> [InternalId={internal_id}] Queued mail for delivery\r\n"
    return f"250 2.0.0 Ok: queued as {queue_id}\r\n"

def recv_line(sock, timeout=30):
    """Read one SMTP line terminated by \\r\\n or \\n, with status."""
    sock.settimeout(timeout)
    buf = b''
    while True:
        try:
            ch = sock.recv(1)
        except socket.timeout:
            return '', 'timeout'
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            return '', f"recv_error:{type(e).__name__}"
        if not ch:
            line = buf.decode('utf-8', errors='replace').strip()
            return line, ('peer_closed' if not line else 'ok')
        if ch == b'\n':
            return buf.decode('utf-8', errors='replace').strip(), 'ok'
        if ch == b'\r':
            continue
        buf += ch

def trace(session_id, client_ip, stage, **fields):
    if not SMTP_TRACE_ENABLED:
        return
    if SMTP_TRACE_IP and client_ip != SMTP_TRACE_IP:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    base = f"SMTPTRACE sid={session_id} ip={client_ip} stage={stage}"
    print(f"{base} {suffix}".rstrip(), flush=True)

def b64decode(s):
    """Decode a base64 string, returning '' on any error."""
    try:
        return base64.b64decode(s.strip()).decode('utf-8', errors='replace')
    except Exception:
        return ''

def extract_addr(raw):
    """Pull address out of 'MAIL FROM:<addr>' or 'RCPT TO:<addr>' line."""
    raw = raw.strip()
    if '<' in raw and '>' in raw:
        addr = raw[raw.index('<') + 1:raw.index('>')]
        return '<none>' if addr == '' else addr
    return raw

def emit_smtp_knock(
    client_ip,
    *,
    stage,
    username=None,
    password=None,
    mail_from=None,
    rcpt_to=None,
    subject=None,
    body=None,
):
    knock = {"type": "KNOCK", "proto": "SMTP", "ip": client_ip, "smtp_stage": stage}
    if username is not None:
        knock["user"] = username
    if password is not None:
        knock["pass"] = password
    if mail_from:
        knock["smtp_mail_from"] = mail_from
    if rcpt_to:
        knock["smtp_rcpt_to"] = rcpt_to
    if subject:
        knock["subject"] = subject
    if body:
        knock["body"] = body
    print(json.dumps(knock), flush=True)

def emit_smtp_diag(client_ip, session_id, **fields):
    payload = {
        "type": "SMTP_DIAG",
        "proto": "SMTP",
        "ip": client_ip,
        "session_id": session_id,
    }
    payload.update(fields)
    print(json.dumps(payload), flush=True)

def classify_no_knock_reason(*, commands_seen, stop_reason, tls_active, authed, saw_starttls, saw_auth, saw_mail, saw_rcpt, saw_data, saw_unrecognized):
    if authed or saw_auth:
        return "auth_without_emit", "AUTH seen but no auth knock emitted"
    if commands_seen == 0:
        if stop_reason.startswith('exception:') or stop_reason.startswith('recv_recv_error:'):
            return "connect_reset", "connection reset or socket error before SMTP commands"
        if stop_reason == 'empty_line':
            return "connect_empty", "client sent blank line then disconnected"
        return "connect_only", "client connected and disconnected without SMTP commands"
    if saw_starttls and not saw_mail and not saw_rcpt and not saw_data:
        return "starttls_only", "client negotiated STARTTLS but did not continue into envelope/auth"
    if saw_mail or saw_rcpt:
        return "envelope_partial", "partial envelope only (MAIL/RCPT without knockable message/auth path)"
    if saw_data:
        return "data_without_envelope", "DATA attempted without valid envelope state"
    if saw_unrecognized:
        return "non_smtp_probe", "non-SMTP probe payload or unrecognized command sequence"
    if tls_active and stop_reason in ('recv_peer_closed', 'empty_line'):
        return "tls_drop_after_upgrade", "client dropped after TLS upgrade before knockable commands"
    return "no_knock_path", "session did not reach AUTH or envelope/message knock emission path"

def handle_connection(client_sock, client_ip):
    session_id = uuid.uuid4().hex[:8]
    started_at = time.time()
    stop_reason = 'unknown'
    commands_seen = 0
    knocks_emitted = 0
    last_cmd = ''
    username = None
    password = None
    authed = False
    auth_emitted = False
    mail_from = None
    rcpt_to = None
    subject = None
    messages = 0
    saw_starttls = False
    saw_auth = False
    saw_mail = False
    saw_rcpt = False
    saw_data = False
    saw_unrecognized = False

    tls_active = False

    def emit_knock(stage, **kwargs):
        nonlocal knocks_emitted
        emit_smtp_knock(client_ip, stage=stage, **kwargs)
        knocks_emitted += 1
        trace(
            session_id,
            client_ip,
            'emit',
            knock_stage=stage,
            knock_count=knocks_emitted,
            authed=authed,
            have_from=bool(mail_from),
            have_to=bool(rcpt_to),
        )

    try:
        client_sock.settimeout(30)
        print(f"🔌 SMTP connect {client_ip}", flush=True)
        trace(session_id, client_ip, 'connect', require_auth=SMTP587_REQUIRE_AUTH, fingerprint=SMTP_FINGERPRINT)
        client_sock.sendall(_BANNER)

        while True:
            line, recv_status = recv_line(client_sock)
            if recv_status != 'ok':
                stop_reason = f"recv_{recv_status}"
                trace(session_id, client_ip, 'recv_end', reason=stop_reason, commands_seen=commands_seen, knocks_emitted=knocks_emitted)
                break
            if not line:
                stop_reason = 'empty_line'
                trace(session_id, client_ip, 'recv_empty', commands_seen=commands_seen)
                break

            cmd = line.upper()
            cmd_word = cmd.split(' ', 1)[0]
            last_cmd = cmd_word
            commands_seen += 1
            trace(session_id, client_ip, 'command', cmd=cmd_word, idx=commands_seen)

            if cmd.startswith('EHLO') or cmd.startswith('HELO'):
                client_sock.sendall(_EHLO_RESP_TLS if tls_active else _EHLO_RESP)

            elif cmd == 'STARTTLS':
                saw_starttls = True
                if tls_active:
                    client_sock.sendall(b"503 5.5.1 TLS already active\r\n")
                    continue
                try:
                    client_sock.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    tls_ctx.load_cert_chain(certfile=SMTP_TLS_CERT_PATH, keyfile=SMTP_TLS_KEY_PATH)
                    client_sock = tls_ctx.wrap_socket(client_sock, server_side=True)
                    client_sock.settimeout(30)
                    tls_active = True
                    trace(session_id, client_ip, 'tls_started', cert=SMTP_TLS_CERT_PATH, key=SMTP_TLS_KEY_PATH)
                    # RFC-wise client should issue EHLO again after STARTTLS.
                    continue
                except Exception as e:
                    stop_reason = f"starttls_failed:{type(e).__name__}"
                    trace(session_id, client_ip, 'tls_failed', error=type(e).__name__, detail=str(e))
                    break

            elif cmd.startswith('AUTH PLAIN'):
                saw_auth = True
                parts = line.split(' ', 2)
                if len(parts) == 3 and parts[2].strip():
                    decoded = b64decode(parts[2])
                else:
                    client_sock.sendall(b"334 \r\n")
                    auth_line, auth_status = recv_line(client_sock)
                    if auth_status != 'ok':
                        stop_reason = f"auth_plain_{auth_status}"
                        trace(session_id, client_ip, 'auth_plain_recv_end', reason=stop_reason)
                        break
                    decoded = b64decode(auth_line)
                fields = decoded.split('\x00')
                if len(fields) >= 3:
                    username, password = fields[1], fields[2]
                elif len(fields) == 2:
                    username, password = fields[0], fields[1]
                else:
                    username, password = decoded, ''
                authed = True
                emit_knock(
                    'auth',
                    username=username,
                    password=password or '',
                )
                auth_emitted = True
                client_sock.sendall(b"235 2.7.0 Authentication successful\r\n")

            elif cmd.startswith('AUTH LOGIN'):
                saw_auth = True
                client_sock.sendall(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
                user_line, user_status = recv_line(client_sock)
                if user_status != 'ok':
                    stop_reason = f"auth_login_user_{user_status}"
                    trace(session_id, client_ip, 'auth_login_user_recv_end', reason=stop_reason)
                    break
                username = b64decode(user_line)
                client_sock.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                pass_line, pass_status = recv_line(client_sock)
                if pass_status != 'ok':
                    stop_reason = f"auth_login_pass_{pass_status}"
                    trace(session_id, client_ip, 'auth_login_pass_recv_end', reason=stop_reason)
                    break
                password = b64decode(pass_line)
                authed = True
                emit_knock(
                    'auth',
                    username=username,
                    password=password or '',
                )
                auth_emitted = True
                client_sock.sendall(b"235 2.7.0 Authentication successful\r\n")

            elif cmd.startswith('MAIL FROM:'):
                saw_mail = True
                # New envelope transaction starts here.
                mail_from = extract_addr(line[10:])
                rcpt_to = None
                subject = None
                if SMTP587_REQUIRE_AUTH and not authed:
                    client_sock.sendall(b"530 5.5.1 Authentication required\r\n")
                else:
                    client_sock.sendall(b"250 2.1.0 Ok\r\n")

            elif cmd.startswith('RCPT TO:'):
                saw_rcpt = True
                if rcpt_to is None:
                    rcpt_to = extract_addr(line[8:])
                if SMTP587_REQUIRE_AUTH and not authed:
                    client_sock.sendall(b"530 5.5.1 Authentication required\r\n")
                else:
                    client_sock.sendall(b"250 2.1.5 Ok\r\n")

            elif cmd == 'DATA':
                saw_data = True
                if mail_from is None:
                    client_sock.sendall(b"503 5.5.1 Error: need MAIL command\r\n")
                elif SMTP587_REQUIRE_AUTH and not authed:
                    client_sock.sendall(b"530 5.5.1 Authentication required\r\n")
                else:
                    client_sock.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")

                    # Read headers, capture Subject
                    client_sock.settimeout(15)
                    for _ in range(200):
                        hdr, hdr_status = recv_line(client_sock, timeout=15)
                        if hdr_status != 'ok':
                            trace(session_id, client_ip, 'data_header_recv_end', status=hdr_status)
                            break
                        if not hdr or hdr == '.':
                            break
                        if hdr.upper().startswith('SUBJECT:'):
                            subject = hdr[8:].strip()[:200]

                    # Capture message body (up to 2000 chars)
                    body_lines = []
                    for _ in range(500):
                        body_line, body_status = recv_line(client_sock, timeout=10)
                        if body_status != 'ok':
                            trace(session_id, client_ip, 'data_body_recv_end', status=body_status, lines=len(body_lines))
                            break
                        if body_line == '.':
                            break
                        body_lines.append(body_line)
                    body = '\n'.join(body_lines)[:2000] or None

                    queue_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                    client_sock.sendall(queue_ok_reply(queue_id).encode())

                    # Post-auth message envelope/content event (no creds here; creds are emitted at AUTH stage).
                    emit_knock(
                        'postauth_envelope' if authed else 'preauth_message',
                        mail_from=mail_from,
                        rcpt_to=rcpt_to,
                        subject=subject,
                        body=body,
                    )

                    # Reset for next message in same session
                    mail_from = rcpt_to = subject = None
                    messages += 1
                    if messages >= MAX_MESSAGES_PER_SESSION:
                        client_sock.sendall(b"421 4.7.0 Try again later\r\n")
                        stop_reason = 'max_messages_reached'
                        trace(session_id, client_ip, 'session_limit', max_messages=MAX_MESSAGES_PER_SESSION)
                        break

            elif cmd == 'NOOP':
                client_sock.sendall(b"250 2.0.0 Ok\r\n")

            elif cmd == 'RSET':
                mail_from = rcpt_to = subject = None
                client_sock.sendall(b"250 2.0.0 Ok\r\n")

            elif cmd.startswith('VRFY'):
                client_sock.sendall(b"252 2.0.0 Send some mail, I'll try my best\r\n")

            elif cmd == 'QUIT':
                client_sock.sendall(b"221 Bye\r\n")
                stop_reason = 'quit'
                break

            else:
                saw_unrecognized = True
                client_sock.sendall(b"502 5.5.2 Error: command not recognized\r\n")
                trace(session_id, client_ip, 'command_unrecognized', cmd=cmd_word)

    except Exception as e:
        stop_reason = f"exception:{type(e).__name__}"
        trace(session_id, client_ip, 'handler_exception', error=type(e).__name__, detail=str(e))
    finally:
        # Backstop: if auth succeeded but event emission was skipped for any reason.
        if authed and username is not None and not auth_emitted:
            emit_knock(
                'auth',
                username=username,
                password=password or '',
                mail_from=mail_from,
                rcpt_to=rcpt_to,
            )
        duration_ms = int((time.time() - started_at) * 1000)
        no_knock_reason = None
        no_knock_detail = None
        if knocks_emitted == 0:
            no_knock_reason, no_knock_detail = classify_no_knock_reason(
                commands_seen=commands_seen,
                stop_reason=stop_reason,
                tls_active=tls_active,
                authed=authed,
                saw_starttls=saw_starttls,
                saw_auth=saw_auth,
                saw_mail=saw_mail,
                saw_rcpt=saw_rcpt,
                saw_data=saw_data,
                saw_unrecognized=saw_unrecognized,
            )
        trace(
            session_id,
            client_ip,
            'session_summary',
            duration_ms=duration_ms,
            stop_reason=stop_reason,
            commands_seen=commands_seen,
            messages=messages,
            knocks_emitted=knocks_emitted,
            tls_active=tls_active,
            authed=authed,
            auth_emitted=auth_emitted,
            last_cmd=last_cmd,
            have_from=bool(mail_from),
            have_to=bool(rcpt_to),
            no_knock_reason=no_knock_reason,
            no_knock_detail=no_knock_detail,
            saw_starttls=saw_starttls,
            saw_auth=saw_auth,
            saw_mail=saw_mail,
            saw_rcpt=saw_rcpt,
            saw_data=saw_data,
        )
        if no_knock_reason is not None:
            emit_smtp_diag(
                client_ip,
                session_id,
                event='no_knock',
                duration_ms=duration_ms,
                commands_seen=commands_seen,
                stop_reason=stop_reason,
                no_knock_reason=no_knock_reason,
                no_knock_detail=no_knock_detail,
                tls_active=tls_active,
                authed=authed,
                last_cmd=last_cmd,
                saw_starttls=saw_starttls,
                saw_auth=saw_auth,
                saw_mail=saw_mail,
                saw_rcpt=saw_rcpt,
                saw_data=saw_data,
            )
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
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 587))
    sock.listen(100)
    print(f"🚀 SMTP Honeypot Active on Port 587 (IPv4+IPv6) [{SMTP_FINGERPRINT}]. Collecting radiation...", flush=True)

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            trace(f"b{uuid.uuid4().hex[:8]}", client_ip, 'blocked_accept')
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()
