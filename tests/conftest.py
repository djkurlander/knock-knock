"""Shared fixtures for honeypot integration tests."""
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import unittest.mock

import pytest

# Stub heavy optional deps so test_unit.py can import monitor.py on machines
# that don't have the full requirements installed (e.g. a dev laptop).
# In CI, pip install -r requirements.txt runs first, so the real modules load.
for _mod in (
    'geoip2', 'geoip2.database',
    'impacket', 'impacket.examples', 'impacket.examples.secretsdump',
    'impacket.ntlm', 'impacket.spnego',
):
    sys.modules.setdefault(_mod, unittest.mock.MagicMock())

HONEYPOTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'honeypots')


def _pipe_to_queue(pipe, q):
    for raw in pipe:
        line = raw.decode('utf-8', errors='replace').strip()
        if line:
            q.put(line)


def wait_for_port(port, host='127.0.0.1', timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} did not open within {timeout}s")


@pytest.fixture
def honeypot_proc(tmp_path):
    """
    Factory fixture.  Call as:
        proc, q = honeypot_proc('ftp_honeypot.py', port=12121)
        proc, q = honeypot_proc('ssh_honeypot_asyncssh.py', port=12022,
                                 env={'SSH_PORT': '12022'})

    The subprocess is started with DB_DIR pointing at a per-test tmp dir so
    it never touches the real data/ directory.  Redis is pointed at localhost
    but is_blocked() silently ignores connection failures, so Redis doesn't
    need to be running.
    """
    started = []

    def start(script, port, args=(), env=None):
        base_env = {
            **os.environ,
            'REDIS_HOST': '127.0.0.1',
            'DB_DIR': str(tmp_path),
        }
        if env:
            base_env.update(env)
        cmd = [sys.executable, os.path.join(HONEYPOTS_DIR, script)] + list(args)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=base_env,
            cwd=HONEYPOTS_DIR,
        )
        q = queue.Queue()
        threading.Thread(target=_pipe_to_queue, args=(proc.stdout, q), daemon=True).start()
        wait_for_port(port)
        started.append(proc)
        return proc, q

    yield start

    for proc in started:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
