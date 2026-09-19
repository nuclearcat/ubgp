#!/usr/bin/env python3
"""CLI, detach, syslog and reload checks; Docker only."""
import ctypes
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

assert Path("/.dockerenv").exists(), "Run CLI tests inside Docker only"
BIN = "/work/target/release/ubgp"
# Reap the detached child ourselves rather than relying on the container's PID 1.
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0


def command(*args, cwd=None):
    return subprocess.run([BIN, *args], cwd=cwd, capture_output=True, text=True, timeout=5)


def wait_for(label, predicate):
    """Poll for up to eight seconds, printing success or raising a labeled assertion."""
    end = time.monotonic() + 8
    while time.monotonic() < end:
        if predicate():
            print("PASS", label, flush=True)
            return
        time.sleep(0.05)
    raise AssertionError(label)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def processes(config_name):
    """Find ubgp PIDs whose command lines contain the configuration name."""
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                if os.readlink(entry / "exe") == BIN and config_name.encode() in (entry / "cmdline").read_bytes():
                    found.append(int(entry.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
    return found


help_result = command("--help")
assert help_result.returncode == 0 and "--daemon" in help_result.stdout
assert "/etc/ubgp.toml" in help_result.stdout
for args in [("--config",), ("--config=",), ("-c", "--daemon"), ("--bad-flag",)]:
    assert command(*args).returncode != 0
print("PASS help and invalid CLI arguments", flush=True)

logs = []
stopping = threading.Event()
syslog_path = Path("/dev/log")
assert not syslog_path.exists(), "Test requires an isolated /dev/log"
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.bind(str(syslog_path))
sock.settimeout(0.1)


def collect():
    """Collect local syslog datagrams until the test signals this thread to stop."""
    while not stopping.is_set():
        try:
            logs.append(sock.recv(65536).decode(errors="replace"))
        except socket.timeout:
            pass


collector = threading.Thread(target=collect)
collector.start()
pid = None
config_name = "relative%config.toml"
try:
    with tempfile.TemporaryDirectory(prefix="ubgp-cli-") as directory:
        config = Path(directory) / config_name
        port = unused_port()
        text = Path("examples/ubgp.toml").read_text().replace('"192.0.2.1"', '"127.0.0.1"')
        text = text.replace('"192.0.2.2"', '"127.0.0.2"').replace('"eth0"', '"lo"')
        text = text.replace("listen_port = 179", f"listen_port = {port}")
        text = text.replace("\nport = 179", "\nport = 9")
        config.write_text(text)
        for flags in [[], ["--debug"]]:
            env = os.environ.copy()
            env.pop("RUST_LOG", None)
            if flags:
                env["RUST_LOG"] = "off"  # Explicit --debug wins.
            process = subprocess.Popen([BIN, "-c", str(config), *flags], env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                wait_for("foreground listener ready", lambda: listening(port))
                time.sleep(0.3)
            finally:
                process.terminate()
                output, _ = process.communicate(timeout=5)
            assert process.returncode == 0, output
            assert "BGP Connect" in output, output
            assert ("kernel snapshot reconciled" in output) == bool(flags), output
        print("PASS quiet default and --debug override", flush=True)
        for args in [("-c", config_name, "--check-config"), (f"--config={config_name}", "--daemon", "--check-config")]:
            result = command(*args, cwd=directory)
            assert result.returncode == 0 and "configuration valid" in result.stdout, result
            assert not processes(config_name), "--check-config must not detach"
        config.write_text("invalid = true\n")
        result = command("--daemon", "--config", config_name, cwd=directory)
        assert result.returncode != 0 and not processes(config_name)
        print("PASS validation precedes detachment", flush=True)
        config.write_text(text)
        result = command("-d", f"--config={config_name}", cwd=directory)
        assert result.returncode == 0, result.stderr
        wait_for("daemon survives launcher exit", lambda: len(processes(config_name)) == 1)
        pid = processes(config_name)[0]
        assert os.getsid(pid) != os.getsid(0)
        assert os.readlink(f"/proc/{pid}/cwd") == "/"
        for fd in range(3):
            assert os.readlink(f"/proc/{pid}/fd/{fd}") == "/dev/null"
        wait_for("daemon initializes BGP listener", lambda: listening(port))
        wait_for("daemon logs to syslog", lambda: any(f"ubgp[{pid}]" in line and "ubgp started" in line and config_name in line for line in logs))
        config.write_text(text.replace('export_acl = "export"', 'export_acl = "missing"'))
        os.kill(pid, signal.SIGHUP)
        wait_for("syslog preserves warning severity", lambda: any(line.startswith("<28>") and "reload rejected" in line for line in logs))
        assert listening(port)
        next_port = unused_port()
        config.write_text(text.replace(f"listen_port = {port}", f"listen_port = {next_port}"))
        os.kill(pid, signal.SIGHUP)
        wait_for("relative config path reloads after chdir", lambda: listening(next_port))
        os.kill(pid, signal.SIGTERM)
        wait_for("daemon shuts down on SIGTERM", lambda: not processes(config_name))
        reaped, status = os.waitpid(pid, 0)
        assert reaped == pid and os.waitstatus_to_exitcode(status) == 0
        pid = None
        logs.clear()
        result = command("--daemon", "--debug", "-c", str(config))
        assert result.returncode == 0, result.stderr
        wait_for("debug daemon started", lambda: len(processes(config_name)) == 1)
        pid = processes(config_name)[0]
        wait_for("debug diagnostics reach syslog with debug severity", lambda: any(line.startswith("<31>") and "kernel snapshot reconciled" in line for line in logs))
        os.kill(pid, signal.SIGTERM)
        wait_for("debug daemon shuts down", lambda: not processes(config_name))
        os.waitpid(pid, 0)
        pid = None
        print("All Docker CLI/daemon tests passed", flush=True)
finally:
    for child in processes(config_name):
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
    if pid is not None:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
    stopping.set()
    collector.join()
    sock.close()
    syslog_path.unlink()
