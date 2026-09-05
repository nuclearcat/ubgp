# Validation results — 2026-09-05

Final validation ran inside Docker, using Rust 1.97.1 and BIRD 2.0.12.
Containers used `--network none`; live tests created a veth pair and a second
network namespace inside the container with NET_ADMIN and SYS_ADMIN.
No host network configuration or sysctls were changed.

| Check | Result |
| --- | --- |
| Rust formatting and Clippy, warnings denied | Passed |
| Unit tests | 18 passed |
| Example configuration validation | Passed |
| eBGP and iBGP against BIRD | Passed |
| Active, incoming and simultaneous connections | Passed |
| IPv4/IPv6 NLRI and IPv6 transport | Passed |
| Four-octet ASNs and next-hop self | Passed |
| Selected tables, connected routes and mandatory ACLs | Passed |
| Duplicate-route deletion and route-type replacement | Passed |
| IPv4/IPv6 withdrawals and received-route discard | Passed |
| Invalid ACL reload preserves running configuration | Passed |
| Prefix-capacity failure withdraws stale exports and later recovers | Passed; withdrawal observed at 3.04 s with a 3 s test deadline |
| Forced ENOBUFS and lost-delete recovery | Passed with 10,000 and 100,000 route floods |
| 8,192 dummy interfaces with connected routes | Passed |
| Final scale-test BIRD export count | 108,193 prefixes, as expected |
| Scale-test ubgp peak RSS / final RSS | 19,988 KiB / 15,044 KiB |
| Synthetic 1,000,000-prefix decode/deduplication benchmark | Passed; 232.9 ms |

The scale test created 8,192 interfaces in 5.85 s and inserted 100,000 kernel
routes in 0.45 s while ubgp was paused. It then resumed ubgp, observed netlink
loss detection, verified that the lost deletion was withdrawn, and observed
the final prefix count at BIRD. The synthetic million-prefix test includes
input construction and runs separately from the live kernel test.

These are measurements from this test environment, not production throughput
guarantees. The daemon uses coalesced complete table dumps, so sustained churn
cost depends on the selected-table size and ACL configuration. The scale run
used a deliberately small 64 KiB requested netlink receive buffer to provoke
loss; the production default is 64 MiB.

See [README.md](README.md) for reproducible Docker commands and the supported
protocol scope. No live tests have been run on a production router.

## CLI and background-mode update

The CLI update passed formatting, Clippy with warnings denied, and 21 unit
tests (18 existing tests plus three argument-parser tests) inside Docker.
Docker process tests verified help/error handling, config validation before
forking, `--check-config` staying in the foreground, daemon survival after
launcher exit, detached standard streams, BGP listener startup, syslog output
and warning severity, relative-path SIGHUP reloads after changing directory,
and clean SIGTERM shutdown. The BIRD integration suite, including the
10,000-route loss/recovery test, also passed after the startup changes.
The larger scale measurements above are from the preceding implementation.

## TCP-MD5 update

Formatting, Clippy with warnings denied, and 22 unit tests passed inside Docker.
The CLI process tests and core BIRD integration suite, including 10,000-route
loss/recovery, also passed. TCP-MD5 interoperability passed against BIRD for
IPv4 and IPv6 transport in both active and incoming modes. Tests verified
rejection of mismatched and missing keys, SIGHUP key rotation and removal,
and three peers sharing a listener with two distinct keys and one unauthenticated
peer. Changing one peer to another peer's key blocked that session without
interrupting the other two. Configuration/debug errors and daemon logs were
checked for test-key disclosure. Each live suite runs in its own network
namespace inside Docker so routes and interfaces cannot carry over between suites.

## Connection diagnostics update

Docker validation passed Clippy with warnings denied, 23 unit tests, CLI/daemon
process tests, the core BIRD integration suite, and TCP-MD5 interoperability tests.
A regression test verifies that an outgoing setup error survives connection
selection when no incoming peer connects. Live tests assert TCP connected,
OpenSent, OpenConfirm, and Established logs for outgoing, incoming, and
simultaneous connections, including authenticated IPv4/IPv6 sessions.

## Quiet logging and --debug update

Docker checks passed formatting, Clippy with warnings denied, 23 unit tests,
and CLI/daemon process tests. Process tests verified that normal startup keeps
BGP connection events visible while suppressing routine snapshot logs, that
`--debug` enables snapshots even with `RUST_LOG=off`, and that daemon debug
messages reach syslog with debug severity.

## Management console update

Docker validation passed formatting, Clippy with warnings denied, 23 unit tests,
CLI/daemon process tests, management process tests, and the BIRD and TCP-MD5
integration suites. Management tests covered the default loopback listener,
Telnet option refusal and CR-NUL input, commands and peer failure reasons,
oversized input isolation, listener changes and client closure on SIGHUP,
disabling the listener, and rejecting non-loopback bind addresses. Live BIRD
tests queried Established state and exact ACL export candidates for outgoing,
incoming, IPv4/IPv6, simultaneous, and MD5-authenticated sessions.
