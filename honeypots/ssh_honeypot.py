#!/root/knock-knock/.venv/bin/python
import paramiko
import socket
import threading
import logging
import json
import os
import shutil
from common import create_dualstack_tcp_listener, get_redis_client, is_blocked as is_blocked_common, normalize_ip

_r = get_redis_client()
SSH_HOST_KEY_PATH = os.environ.get('SSH_HOST_KEY_PATH', os.path.join(os.environ.get('DB_DIR', 'data'), 'ssh_host_rsa_key'))
SSH_LEGACY_HOST_KEY_PATH = 'server.key'


def is_blocked(ip):
    return is_blocked_common(_r, ip)
# Log to a file we can tail in real-time
# paramiko.util.log_to_file("honeypot_debug.log") 

# 1. Kill the root logger's interest in anything below CRITICAL
logging.basicConfig(level=logging.CRITICAL)

# 2. Specifically target the 'paramiko' logger
logger = logging.getLogger("paramiko")
logger.setLevel(logging.CRITICAL)
logger.propagate = False

# 3. Add a NullHandler so it has somewhere to send its errors (the void)
logger.addHandler(logging.NullHandler())


class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print(json.dumps({"type": "KNOCK", "proto": "SSH", "ip": self.client_ip, "user": username, "pass": password}), flush=True)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

def handle_connection(client_sock, addr, host_key):
    client_sock.settimeout(20)
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    transport.banner_timeout = 30
    
    server = SSHHoneypot(addr[0])
    try:
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"
        transport.start_server(server=server)
        
        # --- THE FIX IS HERE ---
        # We need to wait for the client to try and authenticate.
        # accept() will wait for a channel request (like a shell), 
        # but the check_auth_password happens internally during this wait.
        chan = transport.accept(20) 
        if chan:
            chan.close()
            
    except (paramiko.SSHException, EOFError, socket.timeout):
        pass 
    except Exception as e:
        print(f"!!! Unexpected error from {addr[0]}: {e}")
    finally:
        transport.close()

def start_honeypot():
    os.makedirs(os.path.dirname(SSH_HOST_KEY_PATH) or '.', exist_ok=True)
    if not os.path.exists(SSH_HOST_KEY_PATH) and os.path.exists(SSH_LEGACY_HOST_KEY_PATH):
        shutil.copyfile(SSH_LEGACY_HOST_KEY_PATH, SSH_HOST_KEY_PATH)
        os.chmod(SSH_HOST_KEY_PATH, 0o600)
    if not os.path.exists(SSH_HOST_KEY_PATH):
        os.makedirs(os.path.dirname(SSH_HOST_KEY_PATH) or '.', exist_ok=True)
        paramiko.RSAKey.generate(2048).write_private_key_file(SSH_HOST_KEY_PATH)
    host_key = paramiko.RSAKey(filename=SSH_HOST_KEY_PATH)

    # Dual-stack socket: accepts both IPv4 and IPv6
    sock = create_dualstack_tcp_listener(22, backlog=100)

    print("🚀 Honeypot Active on Port 22 (IPv4+IPv6). Collecting radiation...")

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        # Check blocklist - reject immediately if blocked
        if is_blocked(client_ip):
            client.close()
            continue
        # 2. Now 'host_key' exists and can be passed to the thread
        threading.Thread(target=handle_connection, args=(client, (client_ip, addr[1]), host_key)).start()

if __name__ == "__main__":
    start_honeypot()
