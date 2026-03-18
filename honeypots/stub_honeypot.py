#!/usr/bin/env python3
import socket
import threading
import argparse
from common import create_dualstack_tcp_listener, is_blocked, normalize_ip

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
    sock = create_dualstack_tcp_listener(port, backlog=100)
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
