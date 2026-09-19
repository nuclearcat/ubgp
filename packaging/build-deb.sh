#!/bin/bash
# Internal entry point for packaging/Dockerfile; use build-debs.sh on the host.
set -euo pipefail
test "${UBGP_PACKAGE_CONTAINER:-}" = 1 || {
  echo 'Run this script through packaging/Dockerfile' >&2; exit 1;
}
test "$(dpkg --print-architecture)" = amd64
. /etc/os-release
case "$ID:$VERSION_ID" in
  debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "Unsupported distribution: $ID $VERSION_ID" >&2; exit 1 ;;
esac

version=$(cargo metadata --no-deps --format-version 1 --locked \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["packages"][0]["version"])')
if [[ -n ${RELEASE_TAG:-} && $RELEASE_TAG != "v$version" ]]; then
  echo "Release tag $RELEASE_TAG must match Cargo.toml version v$version" >&2
  exit 1
fi
# Debian sorts prereleases before the final version when '-' becomes '~'.
deb_version="${version/-/~}-1~${ID}${VERSION_ID}"
dpkg --validate-version "$deb_version"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}

cp -a packaging/debian debian
cat > debian/changelog <<EOF
ubgp ($deb_version) $VERSION_CODENAME; urgency=medium

  * Build ubgp $version for $PRETTY_NAME (amd64).

 -- ubgp contributors <nuclearcat@users.noreply.github.com>  $(date -u -d "@$SOURCE_DATE_EPOCH" -R)
EOF
# Keep the standalone service's /usr/local path; Debian owns /usr/sbin.
sed 's|/usr/local/sbin/ubgp|/usr/sbin/ubgp|' packaging/ubgp.service > debian/ubgp.service
dpkg-buildpackage --build=binary --no-sign --jobs=auto
mkdir -p /out
cp "/ubgp_${deb_version}_amd64.deb" /out/
cd /out
sha256sum ./*.deb > SHA256SUMS
