#!/usr/bin/env python3
"""
SMB1 honeypot test client.
Connects to TARGET_IP:445 using SMB1 only, enumerates shares via srvsvc,
then recursively traverses every non-IPC share reading all files.

Usage:
    python smbtest_v1.py [target_ip] [port]
"""
import logging
import sys

from impacket import smb, smb3structs
from impacket.smbconnection import (
    SMBConnection,
    FILE_ATTRIBUTE_NORMAL,
    FILE_OPEN,
    FILE_READ_DATA,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
)

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
log = logging.getLogger(__name__)


def _share_names(conn):
    shares = conn.listShares()
    result = []
    for entry in shares:
        name = str(entry["shi1_netname"]).rstrip("\x00")
        if name.upper() != "IPC$":
            result.append(name)
    return result


def _list_dir(conn, share, path):
    pattern = f"{path}\\*" if path else "*"
    return conn.listPath(share, pattern)


def _traverse(conn, share, tree_id, path="", depth=0):
    indent = "  " * depth
    try:
        entries = _list_dir(conn, share, path)
    except Exception as e:
        log.warning(f"{indent}[!] listPath failed on '{path or '<root>'}': {e}")
        return

    for entry in entries:
        name = entry.get_longname()
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        if name in (".", ".."):
            continue

        full = f"{path}\\{name}" if path else name
        if entry.is_directory():
            log.info(f"{indent}[DIR]  {full}")
            _traverse(conn, share, tree_id, full, depth + 1)
        else:
            size = entry.get_filesize()
            log.info(f"{indent}[FILE] {full}  ({size} bytes) — reading...")
            _read_file(conn, tree_id, full, indent)


def _read_file(conn, tree_id, path, indent=""):
    file_id = None
    try:
        file_id = conn.openFile(
            tree_id,
            path,
            desiredAccess=FILE_READ_DATA,
            shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            creationOption=smb3structs.FILE_NON_DIRECTORY_FILE,
            creationDisposition=FILE_OPEN,
            fileAttributes=FILE_ATTRIBUTE_NORMAL,
        )
        data = conn.readFile(tree_id, file_id, 0, 1024)
        preview = bytes(data)[:120]
        log.info(f"{indent}       => {preview.decode('utf-8', errors='replace')!r}")
    except Exception as e:
        log.warning(f"{indent}       [!] read failed: {e}")
    finally:
        if file_id is not None:
            try:
                conn.closeFile(tree_id, file_id)
            except Exception:
                pass


def run(server_ip, port=445, username="testuser", password="testpass"):
    log.info(f"Connecting to {server_ip}:{port} with SMB1 ...")
    conn = SMBConnection(
        remoteName=server_ip,
        remoteHost=server_ip,
        sess_port=port,
        preferredDialect=smb.SMB_DIALECT,
    )
    conn.login(username, password)

    try:
        dialect = conn.getDialect()
        log.info(f"Negotiated dialect: {dialect!r}")
        if dialect != smb.SMB_DIALECT:
            raise RuntimeError(f"Server did not negotiate SMB1: got {dialect!r}")

        log.info("Enumerating shares via srvsvc/listShares ...")
        shares = _share_names(conn)
        log.info(f"Shares: {shares}")

        for share in shares:
            log.info(f"\n{'=' * 50}")
            log.info(f"Connecting to \\\\{server_ip}\\{share}")
            log.info("=" * 50)
            tree_id = None
            try:
                tree_id = conn.connectTree(share)
                _traverse(conn, share, tree_id, "")
            except Exception as e:
                log.warning(f"[!] Could not access share {share}: {e}")
            finally:
                if tree_id is not None:
                    try:
                        conn.disconnectTree(tree_id)
                    except Exception:
                        pass
    finally:
        try:
            conn.logoff()
        except Exception:
            pass


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 445
    run(target, port=port)
