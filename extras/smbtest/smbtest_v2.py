#!/usr/bin/env python3
"""
SMB2/3 honeypot test client.
Connects to TARGET_IP:445, authenticates, enumerates shares via NetrShareEnum,
then recursively traverses every non-IPC share reading all files.

Usage:
    python smbtest_v2.py [target_ip]
"""
import sys
import uuid
import logging
import struct

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import (
    Open, CreateDisposition, CreateOptions,
    DirectoryAccessMask, FilePipePrinterAccessMask,
    ImpersonationLevel, ShareAccess, FileAttributes,
)
from smbprotocol.file_info import FileInformationClass

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NetrShareEnum via SRVSVC named pipe (raw DCERPC/NDR)
# ---------------------------------------------------------------------------

def _netr_share_enum(session, server_ip, ipc_tree=None):
    """
    Connect to IPC$, open SRVSVC, bind, call NetrShareEnum level 1.
    Returns (list of share name strings excluding IPC$, ipc_tree).
    Caller is responsible for disconnecting ipc_tree when done with all shares.
    """
    if ipc_tree is None:
        ipc_tree = TreeConnect(session, f"\\\\{server_ip}\\IPC$")
        ipc_tree.connect()

    pipe = Open(ipc_tree, "srvsvc")
    pipe.create(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
        FileAttributes.FILE_ATTRIBUTE_NORMAL,
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
        CreateDisposition.FILE_OPEN,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
    )

    # DCERPC bind to SRVSVC
    SRVSVC_UUID = b'\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88'
    bind = (
        b'\x05\x00\x0b\x03'       # version=5, minor=0, BIND, flags=0x03
        b'\x10\x00\x00\x00'       # frag_len=16+16+4+20=56? let's build properly
        b'\x00\x00'               # auth_len
        b'\x01\x00\x00\x00'       # call_id=1
        b'\xb8\x10'               # max_xmit_frag=4280
        b'\xb8\x10'               # max_recv_frag=4280
        b'\x00\x00\x00\x00'       # assoc_group
        b'\x01\x00\x00\x00'       # num_ctx_items=1
        b'\x00\x00'               # ctx_id=0
        b'\x01\x00'               # num_trans_items=1
        + SRVSVC_UUID
        + b'\x03\x00'             # interface version 3.0
        + b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'  # NDR transfer syntax
        + b'\x02\x00\x00\x00'
    )
    # Fix frag_len
    bind = bind[:8] + struct.pack('<H', len(bind)) + bind[10:]
    pipe.write(bind, 0)
    pipe.read(0, 4096)

    # NetrShareEnum request (level 1, anonymous server name)
    # server_name: NULL pointer (use local)
    # level: 1
    # ctr: SHARE_INFO_1_CONTAINER with NULL pointer + 0 count
    # prefmaxlen: 0xFFFFFFFF
    # resume: NULL
    req_stub = (
        b'\x00\x00\x00\x00'           # server_name: NULL ptr
        b'\x01\x00\x00\x00'           # level = 1
        b'\x01\x00\x00\x00'           # ctr tag = 1
        b'\x00\x00\x00\x00'           # ptr to SHARE_INFO_1_CONTAINER (NULL)
        b'\xff\xff\xff\xff'           # prefmaxlen
        b'\x00\x00\x00\x00'           # resume_handle: NULL ptr
    )
    req = (
        b'\x05\x00\x00\x03'           # version=5, minor=0, PTYPE=REQUEST, flags
        b'\x10\x00\x00\x00'           # packed_drep (little-endian)
        b'\x00\x00'                   # frag_len placeholder (patched below)
        b'\x00\x00'                   # auth_len = 0
        b'\x01\x00\x00\x00'           # call_id = 1
        + struct.pack('<I', len(req_stub))  # alloc_hint (4 bytes)
        + b'\x00\x00'                 # ctx_id = 0
        + b'\x0f\x00'                 # opnum = 15 (NetrShareEnum)
        + req_stub
    )
    req = req[:8] + struct.pack('<H', len(req)) + req[10:]
    pipe.write(req, 0)
    resp = pipe.read(0, 65536)

    pipe.close()
    # Do NOT disconnect ipc_tree — keep the session alive for subsequent tree connects

    # Parse share names from NDR response
    shares = []
    try:
        data = bytes(resp)
        # Find the share count (uint32) after the response headers
        # Response stub starts after 24-byte DCERPC header
        stub = data[24:]
        # level(4) + ctr_tag(4) + ptr(4) + count(4) + ptr(4) + max_count(4) = 24 bytes before entries
        offset = 24
        count = struct.unpack_from('<I', stub, 8)[0]
        # Each SHARE_INFO_1 entry: type(4) + ptr_name(4) + ptr_comment(4) = 12 bytes referent
        # then deferred strings follow
        # Skip the fixed-size referents
        offset = 24 + count * 12
        for _ in range(count):
            if offset + 12 > len(stub):
                break
            # max_count(4) + offset(4) + actual_count(4)
            actual = struct.unpack_from('<I', stub, offset + 8)[0]
            offset += 12
            name_bytes = stub[offset: offset + actual * 2]
            name = name_bytes.decode('utf-16-le').rstrip('\x00')
            shares.append(name)
            # align to 4
            consumed = actual * 2
            offset += consumed + (4 - consumed % 4) % 4
            # skip comment string
            if offset + 12 > len(stub):
                break
            actual2 = struct.unpack_from('<I', stub, offset + 8)[0]
            offset += 12 + actual2 * 2
            consumed2 = actual2 * 2
            offset += (4 - consumed2 % 4) % 4
    except Exception as e:
        log.warning(f"NDR parse error: {e} — falling back to hardcoded shares")
        shares = []

    return [s for s in shares if s.upper() != 'IPC$'], ipc_tree


# ---------------------------------------------------------------------------
# Recursive directory traversal
# ---------------------------------------------------------------------------

def _traverse(tree, path, depth=0):
    indent = '  ' * depth
    dir_open = Open(tree, path or '')
    try:
        dir_open.create(
            ImpersonationLevel.Impersonation,
            DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE,
        )
    except Exception as e:
        log.warning(f"{indent}[!] Cannot open dir '{path or '<root>'}': {e}")
        return

    try:
        entries = dir_open.query_directory(
            '*',
            FileInformationClass.FILE_ID_BOTH_DIRECTORY_INFORMATION,
        )
    except Exception as e:
        log.warning(f"{indent}[!] query_directory failed on '{path or '<root>'}': {e}")
        dir_open.close()
        return

    for entry in entries:
        name_raw = entry['file_name'].get_value()
        # smbprotocol returns file_name as raw UTF-16-LE bytes (BytesField)
        name = name_raw.decode('utf-16-le').rstrip('\x00') if isinstance(name_raw, bytes) else name_raw
        if name in ('.', '..'):
            continue
        full = f"{path}\\{name}" if path else name
        is_dir = bool(entry['file_attributes'].get_value() & 0x10)

        if is_dir:
            log.info(f"{indent}[DIR]  {full}")
            _traverse(tree, full, depth + 1)
        else:
            size = entry['end_of_file'].get_value()
            log.info(f"{indent}[FILE] {full}  ({size} bytes) — reading...")
            _read_file(tree, full, indent)

    dir_open.close()


def _read_file(tree, path, indent=''):
    fh = Open(tree, path)
    try:
        fh.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.FILE_READ_DATA,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        data = fh.read(0, 1024)
        preview = bytes(data)[:120]
        try:
            log.info(f"{indent}       => {preview.decode('utf-8', errors='replace')!r}")
        except Exception:
            log.info(f"{indent}       => {preview!r}")
    except Exception as e:
        log.warning(f"{indent}       [!] read failed: {e}")
    finally:
        try:
            fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(server_ip, username='testuser', password='testpass'):
    log.info(f"Connecting to {server_ip}:445 ...")
    conn = Connection(uuid.uuid4(), server_ip, 445, require_signing=False)
    conn.connect()

    try:
        # require_encryption=False: honeypots can't derive session keys from unknown
        # passwords, so encryption/signing must be disabled for honeypot testing.
        sess = Session(conn, username, password, require_encryption=False)
        sess.connect()
        log.info(f"Authenticated as {username!r}")

        log.info("Enumerating shares via NetrShareEnum ...")
        ipc_tree = None
        try:
            shares, ipc_tree = _netr_share_enum(sess, server_ip)
            log.info(f"Shares: {shares}")
        except Exception as e:
            log.warning(f"Share enum failed ({e}), trying PUBLIC and C$")
            shares = ['PUBLIC', 'C$']

        for share in shares:
            log.info(f"\n{'='*50}")
            log.info(f"Connecting to \\\\{server_ip}\\{share}")
            log.info('='*50)
            try:
                tree = TreeConnect(sess, f"\\\\{server_ip}\\{share}")
                tree.connect()
                _traverse(tree, '')
                tree.disconnect()
            except Exception as e:
                log.warning(f"[!] Could not access share {share}: {e}")

    finally:
        if ipc_tree:
            try:
                ipc_tree.disconnect()
            except Exception:
                pass
        conn.disconnect()
        log.info("Done.")


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    run(target)
