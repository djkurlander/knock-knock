#!/usr/bin/env python3
import socket
import threading
import json
from common import create_dualstack_tcp_listener, is_blocked, normalize_ip, recv_line

MAX_LOGIN_ATTEMPTS = 3

def handle_connection(client_sock, client_ip):
    username = None
    attempts = 0
    try:
        client_sock.settimeout(30)
        print(f"🔌 FTP connect {client_ip}", flush=True)
        client_sock.sendall(b"220 (vsFTPd 3.0.3)\r\n")

        while True:
            line = recv_line(client_sock)
            if not line:
                break
            upper = line.upper()

            if upper.startswith('USER '):
                username = line[5:].strip()
                client_sock.sendall(b"331 Please specify the password.\r\n")

            elif upper.startswith('PASS '):
                password = line[5:].strip()
                knock = {"type": "KNOCK", "proto": "FTP",
                         "ip": client_ip, "user": username or '', "pass": password}
                print(json.dumps(knock), flush=True)
                attempts += 1
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    client_sock.sendall(b"421 Service not available, remote server has closed connection\r\n")
                    break
                client_sock.sendall(b"530 Login incorrect.\r\n")
                username = None  # reset for next attempt

            elif upper == 'QUIT':
                client_sock.sendall(b"221 Goodbye.\r\n")
                break

            else:
                client_sock.sendall(b"530 Please login with USER and PASS.\r\n")

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_honeypot():
    sock = create_dualstack_tcp_listener(21, backlog=100)
    print("🚀 FTP Honeypot Active on Port 21 (IPv4+IPv6). Collecting knocks...", flush=True)
    while True:
        client, addr = sock.accept()
        client_ip = normalize_ip(addr[0])
        if is_blocked(client_ip):
            client.close()
            continue
        threading.Thread(target=handle_connection, args=(client, client_ip), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()
