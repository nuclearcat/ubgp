#!/bin/bash
set -euo pipefail
test -e /.dockerenv || { echo "Tests must run inside Docker" >&2; exit 1; }
case "${1:-unit}" in
  unit)
    cargo fmt --check
    cargo clippy --offline --locked --all-targets -- -D warnings
    cargo test --offline --locked
    cargo run --offline --locked -- --config examples/ubgp.toml --check-config
    python3 -u tests/cli.py
    python3 -u tests/management.py
    ;;
  integration)
    unshare --net -- python3 -u tests/integration.py
    unshare --net -- python3 -u tests/md5.py
    ;;
  md5)
    unshare --net -- python3 -u tests/md5.py
    ;;
  scale)
    cargo test --release --offline --locked million_route_snapshot -- --ignored --nocapture
    UBGP_SCALE=1 unshare --net -- python3 -u tests/integration.py
    ;;
  *) exec "$@" ;;
esac
