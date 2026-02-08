#!/root/knock-knock/.venv/bin/python
import paramiko
import socket
import threading
import logging
import os
import time

BLOCKLIST_FILE = os.environ.get('DB_DIR', 'data') + '/blocklist.txt'
BLOCKLIST_RELOAD_INTERVAL = 60  # seconds

_blocklist_cache = set()
_blocklist_last_load = 0

def get_blocklist():
    """Return cached blocklist, reloading from file every 30 seconds."""
    global _blocklist_cache, _blocklist_last_load
    now = time.time()
    if now - _blocklist_last_load > BLOCKLIST_RELOAD_INTERVAL:
        _blocklist_last_load = now
        if os.path.exists(BLOCKLIST_FILE):
            try:
                with open(BLOCKLIST_FILE, 'r') as f:
                    _blocklist_cache = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
            except:
                pass
    return _blocklist_cache
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
        print(f"[*] KNOCK | {self.client_ip} | {username} | {password}", flush=True)
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

def normalize_ip(ip):
    """Normalize IPv4-mapped IPv6 addresses to plain IPv4."""
    if ip.startswith('::ffff:'):
        return ip[7:]  # Strip ::ffff: prefix
    return ip

def start_honeypot():
    # 1. Load the key from the file you generated earlier
    # Make sure 'server.key' is in the same folder as this script
    host_key = paramiko.RSAKey(filename='server.key')

    # Dual-stack socket: accepts both IPv4 and IPv6
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', 22))
    sock.listen(100)

    print("🚀 Honeypot Active on Port 22 (IPv4+IPv6). Collecting radiation...")

    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        # Check blocklist - reject immediately if blocked
        if client_ip in get_blocklist():
            client.close()
            continue
        # 2. Now 'host_key' exists and can be passed to the thread
        threading.Thread(target=handle_connection, args=(client, (client_ip, addr[1]), host_key)).start()

if __name__ == "__main__":
    start_honeypot()
