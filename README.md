# ubgp

A Linux, announce-only BGP daemon written in Rust. It exports ACL-permitted
kernel prefixes from selected routing tables to directly connected eBGP and
iBGP neighbors. It never installs routes or redistributes received BGP routes.

The default configuration is `/etc/ubgp.toml`. Start with
[`examples/ubgp.toml`](examples/ubgp.toml); change its documentation addresses,
ASNs, interface, table selection and prefix rules before deployment.

```sh
ubgp --config /etc/ubgp.toml --check-config
ubgp --config /etc/ubgp.toml
ubgp --daemon --config /etc/ubgp.toml
```

`-c PATH` and `--config=PATH` also select the configuration file; `-d` is an
alias for `--daemon`. See `ubgp --help` for all flags. `--check-config` always
validates and exits in the foreground, even when combined with `--daemon`.

Background mode validates configuration before detaching, changes directory
to `/`, redirects standard streams to `/dev/null`, and sends logs to syslog
as `ubgp` with facility `daemon` and the appropriate severity. Configure a
syslog receiver on the machine to collect these logs. Relative configuration
paths continue to work for SIGHUP reloads. The launcher exits after detaching;
later runtime failures, such as a failed listener bind, are reported to syslog.
Use foreground mode with the supplied systemd service or a container supervisor.

## Export policy

* Every peer **must** reference a named export ACL, including iBGP peers.
  Missing ACLs, unknown settings and invalid prefix ranges fail validation.
* Rules are ordered, first match wins, with implicit deny. Without a length
  range a rule matches the exact prefix only. An empty ACL permits nothing.
* IPv4 is enabled by default. IPv6 requires both `ipv6 = true` globally and
  `ipv6 = true` on the peer, plus explicit IPv6 ACL permits. Set a peer's
  `ipv4 = false` for IPv6-only advertisements.
* Selected tables contribute their destination-only unicast routes, including
  connected routes. Duplicate prefixes across tables, metrics and multipath
  entries produce one advertisement. The final eligible copy disappearing
  produces a withdrawal. No aggregates are synthesized.
* Local/broadcast, blackhole, unreachable, prohibit, cloned/cache and
  source-specific routes are excluded. Route types, gateways and protocols do
  not become BGP attributes. A unicast route remaining in the kernel during
  link-down remains eligible; this daemon does not probe forwarding reachability.
* ACLs must explicitly permit default routes to export them. Permitting a
  parent network does not implicitly permit its more-specifics.

Example rule allowing `/24` through `/32` within a private aggregate:

```toml
{ action = "permit", prefix = "10.0.0.0/8", min_length = 24, max_length = 32 }
```

## Sessions and next hops

Both active connections and incoming connections from configured peers are
supported. Listeners bind only configured local addresses and interfaces.
The local ASN matching `remote_asn` selects iBGP. Outgoing TTL/hop limit is 1
for both session types; there is no multihop setting.

The implementation supports four-octet ASNs (including AS_TRANS/AS4_PATH
compatibility with old peers), IPv4 unicast, IPv6 MP_REACH/MP_UNREACH,
keepalives, hold timers, reconnect backoff, basic route refresh and BGP ID
connection-collision preference. iBGP sends an empty AS_PATH and LOCAL_PREF
100; eBGP prepends the local ASN. Redistributed routes use ORIGIN INCOMPLETE.

Next-hop self uses `local_address` for its address family. When the NLRI family
differs from the transport family, configure `next_hop_v4` or `next_hop_v6`.
These overrides must still be addresses assigned to the peering interface;
they are checked when a session starts. IPv6 announcements require a
non-link-local IPv6 next hop. A local link-local address is discovered
automatically; `next_hop_v6_link_local` can explicitly select one.
Link-local IPv6 peer addresses are supported; `interface` supplies their scope.
RFC 8950 extended next hops are not negotiated.

At the default log level, ubgp reports outgoing Connect attempts, TCP connection
acceptance/completion, OpenSent, OpenConfirm, Established, and retry delays.
Routine kernel snapshots and export synchronization are debug-only to avoid
route-churn log floods. Enable them with `ubgp --debug` or
`ubgp --daemon --debug`; `--debug` overrides `RUST_LOG` with `ubgp=debug`.
Without the flag, `RUST_LOG` remains available for custom filtering.
Failure warnings include the underlying error chain;
connection warnings also identify the local address, interface, destination port,
and whether MD5 is enabled. Received BGP NOTIFICATIONs include code and subcode.
Foreground logs go to stdout; `--daemon` logs go to syslog. A TCP timeout by itself
does not distinguish a wrong MD5 key from filtering or an unreachable peer.

Optional TCP-MD5 authentication is configured separately on each peer:

```toml
md5_password = "replace-with-shared-secret"
```

Use the same key at both ends. Keys contain 1–80 UTF-8 bytes; an empty key is
rejected. Omit the field for unauthenticated sessions. IPv4 and IPv6 transports,
active connections, incoming connections, and different keys on a shared
listener are supported. Linux installs/verifies TCP signatures before BGP
starts. Key installation failures never fall back to unauthenticated TCP.
The kernel must support `CONFIG_TCP_MD5SIG`.

Changing or removing a key uses the normal SIGHUP reload and reconnects peers;
coordinate key changes at both ends. The key is stored in the TOML file, so
restrict that file to the service account/group. Keys are redacted from Debug
output; TOML parse errors report location without quoting configuration values.

Received UPDATEs are bounded and structurally validated, then discarded.
Malformed protocol messages can reset the session. This is an exporter, not
a complete routing daemon: there is no best-path selection, route reflection,
ADD-PATH, TCP-AO, BFD, graceful restart, VPN/EVPN, or forwarding-plane writes.

## Management console

The read-only console is enabled by default on `127.0.0.1:65090`:

```sh
telnet 127.0.0.1 65090
```

Commands: `help`, `show summary`, `show peers`, `show routes ACL [PREFIX]`,
and `quit`/`exit`. For example, `show routes firewall 100.64.1.2/32` looks up
an exact prefix in the `firewall` ACL export candidates. `show summary` lists
the ACL names and candidate counts. `show peers` reports state, seconds in
that state, MD5 enabled/disabled, and the most recent failure (retained after
reconnection). Keys are never displayed. States reset on configuration reload.

Route queries show the current ACL-filtered kernel snapshot, not the peer's
advertised RIB; family negotiation and connection state can further restrict
exports. Unfiltered listings show at most 100 unordered prefixes. Prefix
lookups are exact, not longest-prefix matches.

Optional configuration:

```toml
[management]
enabled = true
listen = "127.0.0.1:65090"
```

Use `enabled = false` to disable the console. Only loopback addresses are
accepted; the console has no authentication and is accessible to local users.
It supports basic Telnet negotiation and line editing with backspace, as well
as plain TCP clients. Limits are 16 concurrent clients, 512 command bytes,
a five-minute command input deadline, and a five-second write timeout.
SIGHUP closes console connections and applies the new listener settings.

## Netlink recovery and resource use

Linux netlink is lossy. ubgp requests a 64 MiB socket receive buffer and logs
the effective size. Linux caps ordinary SO_RCVBUF by `net.core.rmem_max` and
reports twice the requested capacity for bookkeeping. The deployment tuning
file is [`packaging/90-ubgp.conf`](packaging/90-ubgp.conf). The daemon does not
change sysctls or suppress ENOBUFS notifications.

Notifications are coalesced invalidations. An independent worker builds fresh
route snapshots using strict, kernel-filtered dumps of the selected tables,
then publishes only completed snapshots. There are no per-interface queries
or fixed interface-count arrays. This handles route replacement and multipath
deletion without maintaining a second, potentially inconsistent event-derived
routing table.

`refresh_interval_ms` (default 250) is the minimum pause between completed
refreshes during churn. A pending refresh is not continually postponed by
new notifications. Notifications arriving during a dump schedule another
refresh. Different table/family dumps are not a kernel-wide atomic snapshot;
concurrent changes converge through subsequent refreshes.

ENOBUFS, truncation, overruns, interrupted dumps, malformed dump records,
dump deadlines and prefix-capacity failures discard the staging snapshot and
trigger full retries with capped backoff. Request sockets are recreated for
each attempt. A periodic dump (default 300 seconds) also reconciles state.

Previously advertised state is retained for `stale_timeout_secs` (default 30)
after a refresh becomes necessary. If no complete replacement can be built,
an independent watchdog clears exports, causing withdrawals. It continues
running during failed dumps and ACL evaluation. Successful synchronization
restores advertisements. Peer write deadlines close stuck sessions; no graceful
restart capability is advertised, so remote peers should remove routes when
the connection closes.

This design trades repeated table scans for simpler recovery. During sustained
churn, CPU cost depends on the size of the selected tables and ACLs, not just
the number of changed routes. Tune the refresh interval against required
withdrawal latency. `max_prefixes` defaults to 2,000,000 unique eligible kernel
prefixes, counted **before ACL filtering**. Exceeding it never publishes a
partial result.

ACL results are shared by peers using the same ACL. Watch channels retain the
latest snapshot rather than a queue of every route event. Each peer keeps its
advertised set and a bounded-by-prefix-count diff, with batches of up to 200
prefixes. Slow BGP sockets cannot block the netlink worker. Total memory still
scales with prefixes, distinct ACLs and peer count; it is not a fixed byte cap.

## Build and test entirely in Docker

The image contains Rust, BIRD, iproute2 and Python. Source is copied into it;
tests do not mount the host filesystem or Docker socket. Image construction
downloads dependencies; test execution uses `--network none` and Cargo offline.

```sh
docker build -f tests/Dockerfile -t ubgp-test .

# Formatting, Clippy, unit tests, and example configuration validation:
docker run --rm --network none ubgp-test unit

# Live kernel, eBGP/iBGP, IPv4/IPv6, TCP-MD5, BIRD and netlink-loss tests:
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --pids-limit 256 ubgp-test integration

# Also 8,192 dummy interfaces, 100,000 route notifications, and a synthetic
# 1,000,000-prefix decode/deduplication benchmark:
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --pids-limit 256 ubgp-test scale
```

NET_ADMIN permits test routes and interfaces. SYS_ADMIN permits the second
network namespace used by BIRD inside the container. Neither `--privileged`
nor host networking is used. Network tests refuse to run outside Docker.
The namespace, interfaces and routes disappear when the test container exits.
The scale benchmark reports timing and daemon RSS; it is not a throughput SLA.
Recorded validation results are in [TEST_RESULTS.md](TEST_RESULTS.md).

The integration suite checks selected tables, connected prefixes, ACL denies,
duplicate routes, route-type replacement, withdrawals, IPv6, active/incoming
connections, simultaneous connections, four-byte ASNs, invalid ACL reloads,
capacity-triggered stale withdrawal, and actual receive-buffer overflow by
pausing ubgp while flooding kernel routes.
TCP-MD5 tests cover IPv4/IPv6 active and incoming sessions, wrong or missing
keys, SIGHUP key rotation/removal, and distinct authenticated and unauthenticated
peers sharing a listener. To run only these tests, use `md5` instead of
`integration` with the same Docker options.

To export the Docker-built release binary without running tests on the host:

```sh
docker create --name ubgp-artifact ubgp-test
docker cp ubgp-artifact:/work/target/release/ubgp ./ubgp
docker rm ubgp-artifact
```

## Deployment and reload

Requires Linux 4.20+ for strict filtered netlink dumps. The sample service is
[`packaging/ubgp.service`](packaging/ubgp.service). It runs with a dynamic user,
CAP_NET_RAW for SO_BINDTODEVICE and CAP_NET_BIND_SERVICE for TCP/179. Kernel
route dumps/subscriptions do not require NET_ADMIN.

SIGHUP validates the full new configuration before changing anything. Invalid
configuration leaves the running daemon untouched. A valid reload closes
sessions, starts a fresh kernel snapshot and reconnects with the new policy.
Runtime failures such as an unavailable bind address cause startup failure;
configuration validation does not reserve sockets or verify the live network.
SIGTERM/SIGINT closes sessions and stops workers.

Default logs expose buffer sizing, notification loss, retries, stale withdrawals
and session state. Use `--debug` for successful dump counts, prefix counts,
dump durations, export synchronization and connection-candidate diagnostics.

Protocol references: [BGP-4](https://www.rfc-editor.org/rfc/rfc4271.html),
[multiprotocol BGP](https://www.rfc-editor.org/rfc/rfc4760.html),
[four-octet ASNs](https://www.rfc-editor.org/rfc/rfc6793.html),
[netlink recovery](https://www.man7.org/linux/man-pages/man7/netlink.7.html), and
[interrupted dumps](https://docs.kernel.org/userspace-api/netlink/intro.html).
