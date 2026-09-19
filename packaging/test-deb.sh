#!/bin/bash
# Runs only inside the disposable clean target image in packaging/Dockerfile.
set -euo pipefail
test "${UBGP_PACKAGE_CONTAINER:-}" = 1
shopt -s nullglob
packages=(/out/*.deb)
test "${#packages[@]}" -eq 1
package=${packages[0]}
test "$(dpkg-deb --field "$package" Architecture)" = amd64
. /etc/os-release
package_version=$(dpkg-deb --field "$package" Version)
[[ $package_version == *"-1~${ID}${VERSION_ID}" ]]
upstream_version=${package_version%-1~*}
upstream_version=${upstream_version/\~/-}

# Slim container images deliberately exclude documentation during installation.
# Check the archive directly so these checks also cover its example files.
payload=$(mktemp -d)
dpkg-deb --extract "$package" "$payload"
test -f "$payload/usr/share/doc/ubgp/copyright"
test -f "$payload/usr/share/doc/ubgp/examples/90-ubgp.conf"
test -f "$payload/usr/share/doc/ubgp/examples/ubgp.toml"

export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends "$package"
test "$(/usr/sbin/ubgp --version)" = "ubgp $upstream_version"
/usr/sbin/ubgp --help
/usr/sbin/ubgp --check-config
grep -q '^ExecStart=/usr/sbin/ubgp --config /etc/ubgp.toml$' /lib/systemd/system/ubgp.service
test ! -e /etc/systemd/system/multi-user.target.wants/ubgp.service
dpkg-query --show --showformat='${Conffiles}\n' ubgp | grep -q ' /etc/ubgp.toml '

# Local configuration must survive reinstall and removal, then disappear on purge.
echo '# local configuration retained across package operations' >> /etc/ubgp.toml
config_hash=$(sha256sum /etc/ubgp.toml)
dpkg --install "$package"
test "$(sha256sum /etc/ubgp.toml)" = "$config_hash"
apt-get remove -y ubgp
test ! -e /usr/sbin/ubgp
test "$(sha256sum /etc/ubgp.toml)" = "$config_hash"
apt-get purge -y ubgp
test ! -e /etc/ubgp.toml
test ! -e /lib/systemd/system/ubgp.service
cd /out
sha256sum --check SHA256SUMS
