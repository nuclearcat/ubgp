#!/usr/bin/env python3
"""Management TCP/Telnet console process checks; Docker only."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

assert Path('/.dockerenv').exists(), 'Tests must run inside Docker'
BIN = '/work/target/release/ubgp'


def wait(label, predicate):
    """Poll for up to ten seconds, printing success or raising a labeled assertion."""
    until = time.monotonic() + 10
    while time.monotonic() < until:
        if predicate():
            print('PASS', label, flush=True)
            return
        time.sleep(0.05)
    raise AssertionError(label)


def prompt(sock):
    """Read through the console prompt, rejecting early EOF or an oversized response."""
    data = b''
    while not data.endswith(b'ubgp> '):
        chunk = sock.recv(4096)
        assert chunk, data
        data += chunk
        assert len(data) < 100000
    return data


def command(sock, text):
    """Send a CR-LF-terminated console command and return its decoded response."""
    sock.sendall(text.encode() + b'\r\n')
    return prompt(sock).decode()


with tempfile.TemporaryDirectory(prefix='ubgp-management-') as directory:
    config = Path(directory) / 'config.toml'
    text = Path('examples/ubgp.toml').read_text().replace('"192.0.2.1"', '"127.0.0.1"')
    text = text.replace('"192.0.2.2"', '"127.0.0.2"').replace('"eth0"', '"lo"')
    text = text.replace('listen_port = 179', 'listen_port = 1179').replace('\nport = 179', '\nport = 9')
    text = text.replace('connect_timeout_secs = 10', 'connect_timeout_secs = 1')
    # No management stanza: exercise defaults.
    config.write_text(text)
    logfile = open(Path(directory) / 'log', 'w+')
    proc = subprocess.Popen([BIN, '-c', str(config)], stdout=logfile, stderr=subprocess.STDOUT)
    clients = []
    try:
        def ready():
            """Keep the first successful console connection while checking daemon liveness."""
            assert proc.poll() is None
            try:
                s = socket.create_connection(('127.0.0.1', 65090), timeout=1)
                clients.append(s)
                return True
            except ConnectionRefusedError:
                return False
        wait('default loopback console ready', ready)
        s = clients.pop()
        s.settimeout(3)
        clients.append(s)
        assert b'read-only' in prompt(s)
        s.sendall(bytes([255, 251, 1, 255, 253, 3]) + b'help\r\x00')
        reply = prompt(s)
        assert bytes([255, 254, 1]) in reply and bytes([255, 252, 3]) in reply
        assert b'show summary' in reply
        assert 'AS 64512' in command(s, 'show summary')
        assert '127.0.0.2' in command(s, 'show peers')
        assert 'Unknown ACL' in command(s, 'show routes missing')
        assert 'Invalid prefix' in command(s, 'show routes export invalid')
        assert 'Unknown command' in command(s, 'reload')
        wait('peer failure reason visible', lambda: 'TCP connect failed' in command(s, 'show peers'))
        print('PASS Telnet negotiation, CR-NUL and read-only commands', flush=True)
        with socket.create_connection(('127.0.0.1', 65090), timeout=3) as oversized:
            prompt(oversized)
            oversized.sendall(b'x' * 513)
            try:
                assert oversized.recv(1024) == b''
            except ConnectionResetError:
                pass
        assert 'AS 64512' in command(s, 'show summary')
        print('PASS oversized input closes only offending client', flush=True)
        # Valid reload disconnects clients and moves the listener.
        config.write_text(text + '\n[management]\nlisten = "127.0.0.1:65091"\n')
        os.kill(proc.pid, signal.SIGHUP)
        assert s.recv(1024) == b''
        def new_listener():
            """Probe the reloaded listener and verify summary and quit commands."""
            try:
                with socket.create_connection(('127.0.0.1', 65091), timeout=1) as new:
                    prompt(new)
                    assert 'AS 64512' in command(new, 'show summary')
                    new.sendall(b'quit\r\n')
                    assert b'Bye' in new.recv(1024)
                return True
            except ConnectionRefusedError:
                return False
        wait('reload moves listener and closes old clients', new_listener)
        config.write_text(text + '\n[management]\nenabled = false\n')
        os.kill(proc.pid, signal.SIGHUP)
        def disabled():
            try:
                with socket.create_connection(('127.0.0.1', 65091), timeout=1):
                    return False
            except ConnectionRefusedError:
                return True
        wait('management listener can be disabled', disabled)
        assert proc.poll() is None
        config.write_text(text + '\n[management]\nlisten = "0.0.0.0:65090"\n')
        assert subprocess.run([BIN, '-c', str(config), '--check-config'], capture_output=True).returncode != 0
        print('PASS non-loopback binding rejected', flush=True)
    finally:
        for client in clients:
            client.close()
        proc.terminate()
        proc.wait(timeout=10)
        logfile.seek(0)
        if proc.returncode != 0:
            print(logfile.read())
        logfile.close()
    assert proc.returncode == 0
print('All Docker management tests passed', flush=True)
