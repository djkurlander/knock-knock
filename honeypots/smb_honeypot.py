#!/usr/bin/env python3
import json
import logging
import os
import re
import sys
import threading
import time
import uuid

from impacket import smb
from impacket import smb3structs as smb2
from impacket.smbserver import SimpleSMBServer
from common import is_blocked, normalize_ip


SMB_PORT = int(os.environ.get('SMB_PORT', '445'))
TRACE_ENABLED = os.environ.get('SMB_TRACE', '0').lower() not in ('0', 'false', 'no')
TRACE_IP = os.environ.get('SMB_TRACE_IP', '').strip()
EMIT_DEDUP_WINDOW_SEC = max(1, int(os.environ.get('SMB_DEDUP_WINDOW_SEC', '60')))
SMB_SERVER_NAME = os.environ.get('SMB_SERVER_NAME', 'Windows Server 2019 Standard 10.0').strip() or 'Windows Server 2019 Standard 10.0'
SMB_SERVER_OS = os.environ.get('SMB_SERVER_OS', 'Windows Server 2019 Standard 17763').strip() or 'Windows Server 2019 Standard 17763'
SMB_SERVER_DOMAIN = os.environ.get('SMB_SERVER_DOMAIN', 'WORKGROUP').strip() or 'WORKGROUP'
_dedup_lock = threading.Lock()
_dedup_seen = {}


def _packet_bytes(packet):
    if packet is None:
        return b''
    try:
        getter = getattr(packet, 'getData', None)
        if callable(getter):
            data = getter()
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
    except Exception:
        pass
    try:
        data = bytes(packet)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
    except Exception:
        pass
    return b''


def _ntlm_type_label(packet):
    data = _packet_bytes(packet)
    if not data:
        return None
    sig = b'NTLMSSP\x00'
    idx = data.find(sig)
    if idx == -1 or len(data) < idx + 12:
        return None
    msg_type = int.from_bytes(data[idx + 8:idx + 12], 'little', signed=False)
    return {
        1: 'negotiate',
        2: 'challenge',
        3: 'authenticate',
    }.get(msg_type, f'unknown_{msg_type}')


def _username_kind(raw_username):
    if raw_username is None:
        return 'none'
    txt = str(raw_username).strip()
    if not txt:
        return 'blank'
    lower = txt.lower()
    if lower in ('anonymous', 'anon', 'null'):
        return 'anonymous_marker'
    if lower == 'guest':
        return 'guest'
    return 'present'


def _share_from_path(path):
    if not path:
        return None
    txt = str(path).strip()
    if not txt:
        return None
    txt = txt.replace('/', '\\')
    if txt.startswith('\\\\'):
        parts = [p for p in txt.split('\\') if p]
        if len(parts) >= 2:
            share = parts[1].strip()
            return share or None
    share = txt.strip('\\').strip()
    return share or None


def _extract_share_from_packet(packet):
    data = _packet_bytes(packet)
    if not data:
        return None

    # SMB1 often carries ASCII UNC paths.
    m_ascii = re.search(rb'\\\\[A-Za-z0-9._:-]{1,128}\\([^\\/\x00]{1,128})', data)
    if m_ascii:
        try:
            return _share_from_path('\\\\x\\' + m_ascii.group(1).decode('ascii', errors='ignore'))
        except Exception:
            pass

    # SMB2 TREE_CONNECT typically carries UTF-16LE UNC paths.
    try:
        txt16 = data.decode('utf-16le', errors='ignore')
        m_u16 = re.search(r'\\\\[A-Za-z0-9._:-]{1,128}\\([^\\/\x00]{1,128})', txt16)
        if m_u16:
            return _share_from_path('\\\\x\\' + m_u16.group(1))
    except Exception:
        pass
    return None


def _extract_share_from_conn_data(conn_data):
    if not isinstance(conn_data, dict):
        return None
    for key in ('ConnectedShares', 'connectedShares', 'share', 'Share', 'path', 'Path', 'tree', 'Tree'):
        val = conn_data.get(key)
        if isinstance(val, str):
            share = _share_from_path(val)
            if share:
                return share
        if isinstance(val, (list, tuple, set)):
            for item in val:
                share = _share_from_path(item)
                if share:
                    return share
        if isinstance(val, dict):
            for k in val.keys():
                share = _share_from_path(k)
                if share:
                    return share
            for v in val.values():
                share = _share_from_path(v)
                if share:
                    return share
    return None


def trace(client_ip, stage, **fields):
    if not TRACE_ENABLED:
        return
    if TRACE_IP and client_ip != TRACE_IP:
        return
    suffix = ' '.join(f'{k}={v!r}' for k, v in fields.items())
    base = f"SMBTRACE ip={client_ip} stage={stage}"
    print(f"{base} {suffix}".rstrip(), flush=True)


def _extract_smb2_negotiate_dialects(packet):
    # Returns list[int] dialect ids from SMB2 NEGOTIATE request packet.
    dialects = []
    try:
        if hasattr(packet, '__getitem__'):
            try:
                data = packet['Data']
            except Exception:
                data = None
            if data:
                nego = smb2.SMB2Negotiate(data)
                dialects = [int(d) for d in (nego['Dialects'] or [])]
                return dialects
    except Exception:
        pass
    try:
        raw = _packet_bytes(packet)
        if raw:
            p = smb2.SMB2Packet(raw)
            data = p['Data']
            if data:
                nego = smb2.SMB2Negotiate(data)
                dialects = [int(d) for d in (nego['Dialects'] or [])]
    except Exception:
        pass
    return dialects


def _classify_smb2_family(packet):
    dialects = _extract_smb2_negotiate_dialects(packet)
    if not dialects:
        return None, []
    smb3_dialects = {smb2.SMB2_DIALECT_30, smb2.SMB2_DIALECT_302, smb2.SMB2_DIALECT_311}
    family = 'SMB3' if any(d in smb3_dialects for d in dialects) else 'SMB2'
    return family, dialects


def _set_conn_smb_version(smbServer, connId, connData, version):
    if not version:
        return
    try:
        data = connData if isinstance(connData, dict) else smbServer.getConnectionData(connId, checkStatus=False)
        if not isinstance(data, dict):
            return
        current = str(data.get('knock_smb_version') or '').strip().upper()
        incoming = str(version).strip().upper()
        # Keep SMB3 once detected; later SMB2 hooks should not downgrade it.
        if current == 'SMB3' and incoming == 'SMB2':
            incoming = current
        if not incoming:
            return
        data['knock_smb_version'] = incoming
        smbServer.setConnectionData(connId, data)
    except Exception:
        pass


def apply_server_fingerprint(server):
    smb_server = server.getServer()
    try:
        cfg = smb_server.getServerConfig()
        cfg.set('global', 'server_name', SMB_SERVER_NAME)
        cfg.set('global', 'server_os', SMB_SERVER_OS)
        cfg.set('global', 'server_domain', SMB_SERVER_DOMAIN)
        smb_server.setServerConfig(cfg)
        smb_server.processConfigFile()
        trace('-', 'fingerprint_applied', server_name=SMB_SERVER_NAME, server_os=SMB_SERVER_OS, server_domain=SMB_SERVER_DOMAIN)
    except Exception as e:
        trace('-', 'fingerprint_apply_failed', error=f'{type(e).__name__}: {e}')


def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        stream=sys.stdout,
        force=True,
    )


def install_session_setup_hooks(server):
    smb_server = server.getServer()

    original_smb1_negotiate = smb_server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, None)
    if original_smb1_negotiate is not None:
        def wrapped_smb1_negotiate(connId, smbServer, SMBCommand, recvPacket):
            connData = smbServer.getConnectionData(connId, checkStatus=False)
            _set_conn_smb_version(smbServer, connId, connData, 'SMB1')
            trace(
                normalize_ip(connData.get('ClientIP')) or '-',
                'smb1_negotiate',
                conn_id=connId,
                authenticated=bool(connData.get('Authenticated')),
                packet_len=len(_packet_bytes(recvPacket)),
            )
            return original_smb1_negotiate(connId, smbServer, SMBCommand, recvPacket)
        smb_server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, wrapped_smb1_negotiate)

    original_smb1 = smb_server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, None)
    if original_smb1 is not None:
        def wrapped_smb1(connId, smbServer, SMBCommand, recvPacket):
            connData = smbServer.getConnectionData(connId, checkStatus=False)
            _set_conn_smb_version(smbServer, connId, connData, 'SMB1')
            ntlm_type = _ntlm_type_label(recvPacket)
            trace(
                normalize_ip(connData.get('ClientIP')) or '-',
                'smb1_session_setup',
                conn_id=connId,
                authenticated=bool(connData.get('Authenticated')),
                packet_len=len(_packet_bytes(recvPacket)),
                ntlm_type=ntlm_type or '-',
            )
            return original_smb1(connId, smbServer, SMBCommand, recvPacket)
        smb_server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, wrapped_smb1)

    original_smb1_tree = smb_server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, None)
    if original_smb1_tree is not None:
        def wrapped_smb1_tree(connId, smbServer, SMBCommand, recvPacket):
            connData = smbServer.getConnectionData(connId, checkStatus=False)
            _set_conn_smb_version(smbServer, connId, connData, 'SMB1')
            share = _extract_share_from_packet(recvPacket) or _extract_share_from_conn_data(connData)
            trace(
                normalize_ip(connData.get('ClientIP')) or '-',
                'smb1_tree_connect',
                conn_id=connId,
                authenticated=bool(connData.get('Authenticated')),
                packet_len=len(_packet_bytes(recvPacket)),
                share=share or '-',
            )
            _emit_pending_knock(connData, share)
            return original_smb1_tree(connId, smbServer, SMBCommand, recvPacket)
        smb_server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, wrapped_smb1_tree)

    original_smb2_negotiate = smb_server.hookSmb2Command(smb2.SMB2_NEGOTIATE, None)
    if original_smb2_negotiate is not None:
        def wrapped_smb2_negotiate(connId, smbServer, recvPacket, *extra):
            connData = smbServer.getConnectionData(connId, checkStatus=False)
            smb_family, dialects = _classify_smb2_family(recvPacket)
            _set_conn_smb_version(smbServer, connId, connData, smb_family or 'SMB2')
            trace(
                normalize_ip(connData.get('ClientIP')) or '-',
                'smb2_negotiate',
                conn_id=connId,
                authenticated=bool(connData.get('Authenticated')),
                packet_len=len(_packet_bytes(recvPacket)),
                smb_version=smb_family or 'SMB2',
                dialects=','.join(hex(d) for d in dialects) if dialects else '-',
            )
            return original_smb2_negotiate(connId, smbServer, recvPacket, *extra)
        smb_server.hookSmb2Command(smb2.SMB2_NEGOTIATE, wrapped_smb2_negotiate)

    original_smb2 = smb_server.hookSmb2Command(smb2.SMB2_SESSION_SETUP, None)
    if original_smb2 is not None:
        def wrapped_smb2(connId, smbServer, recvPacket):
            connData = smbServer.getConnectionData(connId, checkStatus=False)
            _set_conn_smb_version(smbServer, connId, connData, 'SMB2')
            ntlm_type = _ntlm_type_label(recvPacket)
            trace(
                normalize_ip(connData.get('ClientIP')) or '-',
                'smb2_session_setup',
                conn_id=connId,
                authenticated=bool(connData.get('Authenticated')),
                packet_len=len(_packet_bytes(recvPacket)),
                ntlm_type=ntlm_type or '-',
            )
            return original_smb2(connId, smbServer, recvPacket)
        smb_server.hookSmb2Command(smb2.SMB2_SESSION_SETUP, wrapped_smb2)

    original_smb2_tree = smb_server.hookSmb2Command(smb2.SMB2_TREE_CONNECT, None)
    if original_smb2_tree is not None:
        def wrapped_smb2_tree(connId, smbServer, recvPacket):
            connData = smbServer.getConnectionData(connId, checkStatus=False)
            _set_conn_smb_version(smbServer, connId, connData, 'SMB2')
            share = _extract_share_from_packet(recvPacket) or _extract_share_from_conn_data(connData)
            trace(
                normalize_ip(connData.get('ClientIP')) or '-',
                'smb2_tree_connect',
                conn_id=connId,
                authenticated=bool(connData.get('Authenticated')),
                packet_len=len(_packet_bytes(recvPacket)),
                share=share or '-',
            )
            _emit_pending_knock(connData, share)
            return original_smb2_tree(connId, smbServer, recvPacket)
        smb_server.hookSmb2Command(smb2.SMB2_TREE_CONNECT, wrapped_smb2_tree)


def normalize_username(username):
    if username is None:
        return None
    if not isinstance(username, str):
        username = str(username)
    username = username.strip()
    if not username:
        return None
    return username.lower()


def should_emit(ip, user, domain, host, version):
    now = time.time()
    key = (ip or '', user or '', domain or '', host or '', version or '')
    with _dedup_lock:
        cutoff = now - EMIT_DEDUP_WINDOW_SEC
        stale = [k for k, ts in _dedup_seen.items() if ts < cutoff]
        for stale_key in stale:
            _dedup_seen.pop(stale_key, None)
        if key in _dedup_seen:
            return False
        _dedup_seen[key] = now
        return True


def _build_knock(ip, user=None, smb_share=None, smb_version=None, smb_domain=None, smb_host=None):
    knock = {
        'type': 'KNOCK',
        'proto': 'SMB',
        'ip': ip,
    }
    if user:
        knock['user'] = user
    if smb_share:
        knock['smb_share'] = smb_share
    if smb_version:
        knock['smb_version'] = smb_version
    if smb_domain:
        knock['smb_domain'] = smb_domain
    if smb_host:
        knock['smb_host'] = smb_host
    return knock


def _conn_meta(connData):
    ip = normalize_ip(connData.get('ClientIP')) if isinstance(connData, dict) else None
    smb_version = (connData.get('knock_smb_version') if isinstance(connData, dict) else None) or ''
    return ip, smb_version.strip()


def _build_pending_knock_data(ip, user, smb_version, domain, host):
    return {
        'ip': ip,
        'user': user,
        'smb_version': smb_version,
        'domain': domain,
        'host': host,
    }


def _emit_knock_with_trace(trace_stage, ip, user=None, smb_share=None, smb_version=None, smb_domain=None, smb_host=None):
    knock = _build_knock(ip, user, smb_share, smb_version, smb_domain, smb_host)
    print(json.dumps(knock), flush=True)
    trace(ip, trace_stage, user=user, smb_share=smb_share,
          smb_version=smb_version, domain=smb_domain, host=smb_host)


def auth_callback(smbServer, connData, domain_name, user_name, host_name):
    client_ip, smb_version = _conn_meta(connData)
    domain_name = (domain_name or '').strip()
    host_name = (host_name or '').strip()
    smb_share = _extract_share_from_conn_data(connData)
    raw_user = user_name
    user_kind = _username_kind(raw_user)
    user_name = normalize_username(raw_user)

    trace(
        client_ip or '-',
        'auth_seen',
        raw_user=raw_user,
        user_kind=user_kind,
        user=user_name,
        smb_share=smb_share,
        smb_version=smb_version,
        domain=domain_name,
        host=host_name,
        authenticated=bool(connData.get('Authenticated')),
    )

    if not client_ip:
        trace('-', 'auth_callback_missing_ip', user=user_name, domain=domain_name, host=host_name)
        return
    if is_blocked(client_ip):
        trace(client_ip, 'blocked', user=user_name, domain=domain_name, host=host_name)
        return
    if not user_name:
        trace(
            client_ip,
            'auth_no_user',
            raw_user=raw_user,
            user_kind=user_kind,
            smb_share=smb_share,
            smb_version=smb_version,
            domain=domain_name,
            host=host_name,
        )
        return
    if not should_emit(client_ip, user_name, domain_name, host_name, smb_version):
        trace(client_ip, 'auth_dedup_skip', user=user_name, smb_version=smb_version, domain=domain_name, host=host_name)
        return

    # Emit immediately at auth time (legacy behavior) so we don't miss
    # sessions that never reach a hooked Tree Connect.
    _emit_knock_with_trace('knock_emitted_auth', client_ip, user_name, smb_share, smb_version, domain_name, host_name)

    # Stash auth data for emission at Tree Connect (when share is known)
    connData['_knock_pending'] = _build_pending_knock_data(client_ip, user_name, smb_version, domain_name, host_name)
    trace(client_ip, 'auth_stashed', user=user_name, smb_version=smb_version, domain=domain_name, host=host_name)


def _emit_pending_knock(connData, share):
    """Emit a stashed knock from auth_callback, now with share info from Tree Connect.
    If no auth was stashed, still emit a minimal tree-connect knock.
    """
    pending = connData.get('_knock_pending')
    if pending:
        _emit_knock_with_trace(
            'knock_emitted_tree',
            pending['ip'],
            pending['user'],
            share,
            pending['smb_version'],
            pending['domain'],
            pending['host'],
        )
        return

    # No stashed auth context (blank/anonymous user path) — still emit tree-connect telemetry.
    ip, smb_version = _conn_meta(connData)
    if not ip:
        return
    _emit_knock_with_trace('knock_emitted_tree_noauth', ip, None, share, smb_version)


def build_server():
    server = SimpleSMBServer(listenAddress='0.0.0.0', listenPort=SMB_PORT, ipv6=False)
    server.setSMB2Support(True)
    server.setDropSSP(False)
    apply_server_fingerprint(server)
    server.setAuthCallback(auth_callback)
    # A random impossible credential forces STATUS_LOGON_FAILURE for normal auth attempts.
    impossible_user = f'__knock_fail_{uuid.uuid4().hex[:12]}'
    zero_hash = '00' * 16
    server.addCredential(impossible_user, 0, zero_hash, zero_hash)
    install_session_setup_hooks(server)
    return server


def main():
    configure_logging()
    print(
        f"🧪 SMB config port={SMB_PORT} trace_enabled={TRACE_ENABLED} "
        f"trace_ip={TRACE_IP or '-'} dedup_window={EMIT_DEDUP_WINDOW_SEC}s "
        f"server_name={SMB_SERVER_NAME!r} server_os={SMB_SERVER_OS!r} server_domain={SMB_SERVER_DOMAIN!r}",
        flush=True,
    )
    try:
        server = build_server()
        print(f"🚀 SMB Honeypot Active on Port {SMB_PORT} (SMB2/NTLM). Collecting knocks...", flush=True)
        server.start()
    except Exception as e:
        print(f"❌ SMB server failed: {type(e).__name__}: {e}", flush=True)
        raise


if __name__ == '__main__':
    main()
