#!/root/knock-knock/.venv/bin/python
import socket
import threading
import os
import argparse
import redis

_r = redis.Redis(host=os.environ.get('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

def is_blocked(ip):
    try:
        return _r.sismember("knock:blocked", ip)
    except Exception:
        return False

def normalize_ip(ip):
    if ip.startswith('::ffff:'):
        return ip[7:]
    return ip

def handle_connection(client_sock, client_ip, proto):
    try:
        print(f"🔌 {proto} connect {client_ip}", flush=True)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_honeypot(port, proto):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', port))
    sock.listen(100)
    print(f"🚀 {proto} Stub Honeypot Active on Port {port} (IPv4+IPv6)", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip, proto), daemon=True).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generic connection-logging honeypot stub")
    parser.add_argument('--port', type=int, required=True, help="Port to listen on")
    parser.add_argument('--proto', required=True, help="Protocol name for log messages")
    args = parser.parse_args()
    start_honeypot(args.port, args.proto)
