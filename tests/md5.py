#!/usr/bin/env python3
"""TCP-MD5 interoperability and rejection tests, confined to Docker."""
import signal
import tempfile
import time
from pathlib import Path
from integration import Lab, run, wait_for

ALPHA = "ubgp-test-alpha"
BETA = "ubgp-test-beta"


def blocked(label, control):
    # Cover BIRD's one-second connect delay and ubgp's three-second timeout.
    end = time.monotonic() + 4
    while time.monotonic() < end:
        assert "Established" not in control("show protocols all ubgp"), label
        time.sleep(0.2)
    print("PASS", label, flush=True)


def reconnect(lab, label):
    wait_for(label, lambda: "Established" in lab.control("show protocols all ubgp"))
    wait_for("authenticated route transfer", lambda: lab.has("10.1.0.0/24"))


def rotation(lab):
    lab.configure(mode="incoming", md5_password=ALPHA, bird_password=ALPHA)
    config = lab.path / "ubgp.toml"
    bird = lab.path / "bird.conf"
    config.write_text(config.read_text().replace(ALPHA, BETA))
    lab.ubgp.send_signal(signal.SIGHUP)
    wait_for("key reload closes previous session", lambda: "Established" not in lab.control("show protocols all ubgp"))
    blocked("old key rejected after reload", lab.control)
    bird.write_text(bird.read_text().replace(ALPHA, BETA))
    lab.control("configure")
    reconnect(lab, "new matching key reconnects")
    config.write_text(config.read_text().replace(f'md5_password = "{BETA}"', ""))
    lab.ubgp.send_signal(signal.SIGHUP)
    wait_for("removing key reconnects session", lambda: "Established" not in lab.control("show protocols all ubgp"))
    bird.write_text(bird.read_text().replace(f'password "{BETA}";', ""))
    lab.control("configure")
    reconnect(lab, "authentication can be explicitly removed at both ends")


def shared_listener(lab):
    lab.configure(mode="incoming", md5_password=ALPHA, bird_password=ALPHA)
    run("ip", "route", "add", "192.0.2.0/24", "dev", "ubgp0")
    extra = []
    for number, key in [(10, BETA), (11, None)]:
        address = f"192.0.2.{number}"
        lab.peer("ip", "addr", "add", address + "/24", "dev", "bird0")
        stanza = lab.config.split("[[peers]]", 1)[1]
        stanza = stanza.replace('address = "192.0.2.2"', f'address = "{address}"')
        stanza = stanza.replace(f'md5_password = "{ALPHA}"', f'md5_password = "{key}"' if key else "")
        extra.append("\n[[peers]]" + stanza)
    (lab.path / "ubgp.toml").write_text(lab.config + "".join(extra))
    lab.ubgp.send_signal(signal.SIGHUP)
    controllers = []
    for number, key in [(10, BETA), (11, None)]:
        auth = f'password "{key}";' if key else ""
        config = lab.path / f"bird-{number}.conf"
        control = lab.path / f"bird-{number}.ctl"
        config.write_text(f'''log stderr all;
router id 192.0.2.{number};
protocol device {{ scan time 1; }}
protocol bgp ubgp {{
 local 192.0.2.{number} port {2200+number} as 64513;
 neighbor 192.0.2.1 port 1179 as 64512;
 direct; {auth}
 connect delay time 1; connect retry time 1; error wait time 1, 2;
 graceful restart off;
 ipv4 {{ import all; export none; }};
}}
''')
        lab.peer("bird", "-p", "-c", str(config))
        process = lab.spawn(f"bird-{number}", "nsenter", "-t", str(lab.namespace.pid), "-n", "bird", "-f",
                            "-c", str(config), "-s", str(control), "-P", str(lab.path / f"bird-{number}.pid"))

        def command(text, process=process, control=control):
            assert process.poll() is None, "extra BIRD process exited"
            if not control.exists():
                return ""
            return run("birdc", "-s", str(control), text)

        controllers.append(command)
        wait_for(f"shared listener peer {number} established", lambda: "Established" in command("show protocols all ubgp"))
        wait_for(f"shared listener peer {number} receives routes", lambda: "[ubgp " in command("show route 198.18.1.0/24 all"))
    reconnect(lab, "first authenticated peer remains established alongside other peers")
    # The second authenticated peer must not accept the first peer's key.
    config = lab.path / "bird-10.conf"
    config.write_text(config.read_text().replace(BETA, ALPHA))
    controllers[0]("configure")
    wait_for("second peer resets on key change", lambda: "Established" not in controllers[0]("show protocols all ubgp"))
    blocked("distinct peer keys cannot be interchanged", controllers[0])
    assert "Established" in controllers[1]("show protocols all ubgp")
    assert "Established" in lab.control("show protocols all ubgp")


with tempfile.TemporaryDirectory(prefix="ubgp-md5-") as directory:
    lab = None
    try:
        lab = Lab(directory)
        for ipv6 in [False, True]:
            for mode in ["outgoing", "incoming"]:
                lab.configure(mode=mode, v6_transport=ipv6, md5_password=ALPHA, bird_password=ALPHA)
                print(f"PASS TCP-MD5 {mode} IPv{6 if ipv6 else 4}", flush=True)
        lab.configure(mode="outgoing", md5_password=ALPHA, bird_password=BETA, expect_established=False)
        blocked("mismatched keys cannot establish outgoing session", lab.control)
        lab.configure(mode="incoming", md5_password=ALPHA, expect_established=False)
        blocked("unsigned incoming session cannot bypass TCP-MD5", lab.control)
        rotation(lab)
        shared_listener(lab)
        logs = (lab.path / "ubgp.log").read_text()
        assert ALPHA not in logs and BETA not in logs, "shared keys leaked to daemon logs"
        print("All Docker TCP-MD5 tests passed", flush=True)
    except BaseException:
        for log in Path(directory).glob("*.log"):
            print(f"\n--- {log.name} (last 60 lines) ---\n" + "\n".join(log.read_text().splitlines()[-60:]), flush=True)
        raise
    finally:
        if lab:
            lab.close()
