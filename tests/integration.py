#!/usr/bin/env python3
"""Live kernel/BIRD tests. Refuses to run outside Docker.

The container starts with --network none. The only extra network namespace
and veth pair are created inside it; no Docker socket or host mount is used.
"""
import ipaddress
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time

assert Path("/.dockerenv").exists(), "Run this test inside Docker only"


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return result.stdout


def wait_for(label, predicate, seconds=30):
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        if predicate():
            print(f"PASS {label} ({time.monotonic() - start:.2f}s)", flush=True)
            return
        time.sleep(0.15)
    raise AssertionError(f"Timed out: {label}")


class Lab:
    def __init__(self, path):
        self.path = Path(path)
        self.processes = []
        self.handles = []
        self.ubgp = self.bird = None
        self.namespace = self.spawn("namespace", "unshare", "--net", "sleep", "86400")
        parent = os.readlink("/proc/self/ns/net")
        wait_for("isolated peer namespace", lambda: self.namespace.poll() is None and
                 os.readlink(f"/proc/{self.namespace.pid}/ns/net") != parent, 5)
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "ubgp0", "type", "veth", "peer", "name", "bird0")
        run("ip", "link", "set", "bird0", "netns", str(self.namespace.pid))
        run("ip", "addr", "add", "192.0.2.1/30", "dev", "ubgp0")
        run("ip", "-6", "addr", "add", "2001:db8:ffff::1/64", "dev", "ubgp0", "nodad")
        run("ip", "link", "set", "ubgp0", "up")
        run("ip", "-6", "addr", "add", "fe80::1/64", "dev", "ubgp0", "nodad")
        self.peer("ip", "link", "set", "lo", "up")
        self.peer("ip", "addr", "add", "192.0.2.2/30", "dev", "bird0")
        self.peer("ip", "-6", "addr", "add", "2001:db8:ffff::2/64", "dev", "bird0", "nodad")
        self.peer("ip", "link", "set", "bird0", "up")
        self.peer("ip", "-6", "addr", "add", "fe80::2/64", "dev", "bird0", "nodad")
        run("ip", "link", "add", "connected0", "type", "dummy")
        run("ip", "link", "set", "connected0", "up")
        run("ip", "addr", "add", "198.18.1.1/24", "dev", "connected0")
        self.add("10.1.0.0/24", 100)
        self.add("10.255.1.0/24", 100)
        self.add("10.2.0.0/24", 300)
        run("ip", "route", "add", "blackhole", "10.3.0.0/24", "table", "100")
        run("ip", "-6", "route", "add", "2001:db8:100::/48", "dev", "lo", "table", "100")

    def peer(self, *args):
        return run("nsenter", "-t", str(self.namespace.pid), "-n", *args)

    def spawn(self, name, *args):
        output = (self.path / f"{name}.log").open("a")
        self.handles.append(output)
        p = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
        self.processes.append(p)
        return p

    def stop(self, p):
        if p is not None and p.poll() is None:
            p.send_signal(signal.SIGCONT)
            p.terminate()
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)

    def configure(self, mode="outgoing", local_as=64512, remote_as=64513, v6_transport=False, maximum=64,
                  md5_password=None, bird_password=None, expect_established=True):
        self.stop(self.ubgp)
        self.stop(self.bird)
        self.mode = mode
        local = "2001:db8:ffff::1" if v6_transport else "192.0.2.1"
        remote = "2001:db8:ffff::2" if v6_transport else "192.0.2.2"
        md5_config = f'md5_password = "{md5_password}"' if md5_password is not None else ""
        bird_auth = f'password "{bird_password}";' if bird_password is not None else ""
        self.config = f'''asn = {local_as}
router_id = "192.0.2.1"
ipv6 = true
listen_port = 1179
[kernel]
tables = [100, 200, 254]
receive_buffer_bytes = 65536
refresh_interval_ms = 100
reconcile_interval_secs = 10
stale_timeout_secs = 3
dump_timeout_secs = 1
max_prefixes = {maximum}
[acls.export]
rules = [
 {{action = "deny", prefix = "10.255.0.0/16", min_length = 16, max_length = 32}},
 {{action = "permit", prefix = "10.0.0.0/8", min_length = 24, max_length = 32}},
 {{action = "permit", prefix = "198.18.0.0/15", min_length = 24, max_length = 32}},
 {{action = "permit", prefix = "2001:db8:100::/48", min_length = 48, max_length = 128}},
]
[[peers]]
address = "{remote}"
local_address = "{local}"
interface = "ubgp0"
remote_asn = {remote_as}
export_acl = "export"
{md5_config}
port = {9999 if mode == "incoming" else 2179}
hold_time_secs = 180
connect_timeout_secs = 3
write_timeout_secs = 3
ipv6 = true
next_hop_v4 = "192.0.2.1"
next_hop_v6 = "2001:db8:ffff::1"
'''
        (self.path / "ubgp.toml").write_text(self.config)
        bird = f'''log stderr all;
router id 192.0.2.2;
protocol device {{ scan time 1; }}
protocol static inject {{ ipv4; route 198.51.100.0/24 blackhole; }}
protocol bgp ubgp {{
 local {remote} port 2179 as {remote_as};
 neighbor {local} port 1179 as {local_as};
 direct;
 passive {"on" if mode == "outgoing" else "off"};
 connect retry time 1;
 connect delay time 1;
 error wait time 1, 2;
 hold time 180;
 graceful restart off;
 {bird_auth}
 ipv4 {{ import all; export filter {{ if net = 198.51.100.0/24 then accept; reject; }}; extended next hop off; }};
 ipv6 {{ import all; export none; }};
}}
'''
        (self.path / "bird.conf").write_text(bird)
        # Validate BIRD's configuration before starting either speaker.
        self.peer("bird", "-p", "-c", str(self.path / "bird.conf"))
        self.bird = self.spawn("bird", "nsenter", "-t", str(self.namespace.pid), "-n", "bird", "-f",
                               "-c", str(self.path / "bird.conf"), "-s", str(self.path / "bird.ctl"),
                               "-P", str(self.path / "bird.pid"))
        self.ubgp = self.spawn("ubgp", "/work/target/release/ubgp", "--config", str(self.path / "ubgp.toml"))
        if not expect_established:
            return
        wait_for(f"{mode} BGP Established", lambda: "Established" in self.control("show protocols all ubgp"))
        for event in ["BGP TCP connected", "BGP OpenSent", "BGP OpenConfirm", "BGP Established"]:
            wait_for(f"lifecycle log: {event}", lambda event=event: event in (self.path / "ubgp.log").read_text())
        wait_for("connected IPv4 prefix", lambda: self.has("198.18.1.0/24"))
        with socket.create_connection(("127.0.0.1", 65090), timeout=3) as console:
            def response():
                data = b""
                while not data.endswith(b"ubgp> "):
                    chunk = console.recv(4096)
                    assert chunk, data
                    data += chunk
                return data.decode()
            response()
            console.sendall(b"show peers\r\n")
            assert "Established" in response()
            console.sendall(b"show routes export 198.18.1.0/24\r\n")
            assert "198.18.1.0/24" in response()
        print("PASS management shows Established and ACL export candidate", flush=True)
        wait_for("selected-table IPv4 prefix", lambda: self.has("10.1.0.0/24"))
        wait_for("IPv6 MP_REACH prefix", lambda: self.has("2001:db8:100::/48"))

    def control(self, command):
        if self.bird.poll() is not None or self.ubgp.poll() is not None:
            raise AssertionError("BGP process exited unexpectedly")
        try:
            return run("birdc", "-s", str(self.path / "bird.ctl"), command)
        except subprocess.CalledProcessError:
            return ""

    def has(self, prefix):
        table = "master6" if ":" in prefix else "master4"
        text = self.control(f"show route table {table} {prefix} all")
        return prefix in text and "[ubgp " in text

    def add(self, prefix, table=100):
        run("ip", "route", "add", prefix, "dev", "lo", "table", str(table))

    def delete(self, prefix, table=100):
        run("ip", "route", "del", prefix, "table", str(table))

    def route_tests(self):
        for prefix in ["10.255.1.0/24", "10.2.0.0/24", "10.3.0.0/24", "0.0.0.0/0"]:
            assert not self.has(prefix), f"unexpected export: {prefix}"
        print("PASS ACL deny, unselected table, blackhole and implicit deny", flush=True)
        assert "198.51.100.0/24" not in run("ip", "route", "show", "table", "all")
        print("PASS received BGP route is not installed in the kernel", flush=True)
        attrs = self.control("show route table master4 10.1.0.0/24 all")
        assert "192.0.2.1" in attrs and "64512" in attrs, attrs
        self.add("10.1.0.0/24", 200)
        self.delete("10.1.0.0/24", 100)
        time.sleep(0.5)
        assert self.has("10.1.0.0/24")
        self.delete("10.1.0.0/24", 200)
        wait_for("withdraw only after last selected-table copy disappears", lambda: not self.has("10.1.0.0/24"))
        self.add("10.1.0.0/24")
        wait_for("route re-addition", lambda: self.has("10.1.0.0/24"))
        run("ip", "route", "replace", "blackhole", "10.1.0.0/24", "table", "100")
        wait_for("unicast-to-blackhole replacement withdrawal", lambda: not self.has("10.1.0.0/24"))
        run("ip", "route", "replace", "10.1.0.0/24", "dev", "lo", "table", "100")
        wait_for("blackhole-to-unicast replacement export", lambda: self.has("10.1.0.0/24"))
        run("ip", "-6", "route", "del", "2001:db8:100::/48", "table", "100")
        wait_for("IPv6 MP_UNREACH withdrawal", lambda: not self.has("2001:db8:100::/48"))
        run("ip", "-6", "route", "add", "2001:db8:100::/48", "dev", "lo", "table", "100")
        wait_for("IPv6 re-addition", lambda: self.has("2001:db8:100::/48"))
        self.control("reload in ubgp")
        wait_for("route refresh replay", lambda: self.has("10.1.0.0/24"))
        # Reject a malformed reload without resetting the existing session.
        (self.path / "ubgp.toml").write_text(self.config.replace('export_acl = "export"', 'export_acl = "missing"'))
        self.ubgp.send_signal(signal.SIGHUP)
        wait_for("invalid ACL reload rejected", lambda: "reload rejected" in (self.path / "ubgp.log").read_text())
        assert self.has("10.1.0.0/24")
        (self.path / "ubgp.toml").write_text(self.config)

    def stale_test(self):
        # Exceed max_prefixes without changing the running config/session.
        batch = "".join(f"route add 10.90.0.{n}/32 dev lo table 100\n" for n in range(100))
        run("ip", "-batch", "-", input=batch)
        wait_for("stale snapshot withdraws previous exports", lambda: not self.has("10.1.0.0/24"), 12)
        assert "kernel state stale" in (self.path / "ubgp.log").read_text()
        assert not self.has("10.90.0.99/32"), "partial over-limit dump was published"
        run("ip", "-batch", "-", input="".join(f"route del 10.90.0.{n}/32 table 100\n" for n in range(100)))
        wait_for("successful resync restores exports", lambda: self.has("10.1.0.0/24"), 12)

    def loss_test(self, count=10000):
        sentinel = "10.99.0.1/32"
        self.add(sentinel)
        wait_for("loss-test sentinel announced", lambda: self.has(sentinel))
        self.ubgp.send_signal(signal.SIGSTOP)
        try:
            base = int(ipaddress.IPv4Address("10.128.0.0"))
            batch = "".join(f"route add {ipaddress.IPv4Address(base+n)}/32 dev lo table 100\n" for n in range(count))
            start = time.monotonic()
            run("ip", "-batch", "-", input=batch)
            self.delete(sentinel)  # This event is behind far more data than SO_RCVBUF.
            print(f"Flooded {count} routes in {time.monotonic()-start:.2f}s", flush=True)
        finally:
            self.ubgp.send_signal(signal.SIGCONT)
        wait_for("netlink ENOBUFS detected", lambda: "netlink loss detected" in (self.path / "ubgp.log").read_text())
        wait_for("lost deletion recovered by dump", lambda: not self.has(sentinel), 90)
        last = str(ipaddress.IPv4Address(base+count-1)) + "/32"
        wait_for("flood's final prefix exported", lambda: self.has(last), 90)
        stats = self.control("show route table master4 protocol ubgp count")
        print(stats, flush=True)
        status = Path(f"/proc/{self.ubgp.pid}/status").read_text()
        print("ubgp memory:", "; ".join(re.findall(r"^Vm(?:RSS|HWM):.*$", status, re.M)), flush=True)

    def scale_interfaces(self):
        count = 8192
        print(f"Creating {count} interfaces inside Docker", flush=True)
        start = time.monotonic()
        batch = "".join(f"link add d{n} type dummy\nlink set d{n} up\n"
                        f"addr add 10.{n//256}.{n%256}.1/24 dev d{n}\n" for n in range(count))
        run("ip", "-batch", "-", input=batch)
        print(f"Created {count} interfaces in {time.monotonic()-start:.2f}s", flush=True)
        wait_for("8192nd connected interface prefix exported", lambda: self.has("10.31.255.0/24"), 90)

    def close(self):
        for p in reversed(self.processes):
            self.stop(p)
        for h in self.handles:
            h.close()


def main():
    with tempfile.TemporaryDirectory(prefix="ubgp-tests-") as directory:
        lab = None
        try:
            lab = Lab(directory)
            lab.configure()
            lab.route_tests()
            lab.stale_test()
            lab.configure(mode="incoming", local_as=64512, remote_as=64512)
            attrs = lab.control("show route table master4 10.1.0.0/24 all")
            assert re.search(r"BGP.local_pref:\s+100", attrs), attrs
            print("PASS incoming iBGP and LOCAL_PREF", flush=True)
            lab.configure(mode="both", local_as=4200000001, remote_as=4200000002, v6_transport=True, maximum=2000000)
            attrs = lab.control("show route table master4 10.1.0.0/24 all")
            assert "4200000001" in attrs, attrs
            print("PASS IPv6 transport, simultaneous connect and four-byte ASN", flush=True)
            if os.environ.get("UBGP_SCALE") == "1":
                lab.scale_interfaces()
                lab.loss_test(100000)
            else:
                lab.loss_test()
            print("All Docker integration tests passed", flush=True)
        except BaseException:
            for log in Path(directory).glob("*.log"):
                print(f"\n--- {log.name} (last 100 lines) ---\n" + "\n".join(log.read_text().splitlines()[-100:]), flush=True)
            raise
        finally:
            if lab:
                lab.close()


if __name__ == "__main__":
    main()
