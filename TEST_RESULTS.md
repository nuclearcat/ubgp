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
