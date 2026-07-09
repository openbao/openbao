#!/usr/bin/env bash

# This script updates a Debian package repository under build/ based on .deb
# packages available under dist/. The repository does not need to exist yet.

set -euo pipefail

case "$VERSION" in
  *-*) SUITE=testing ;;
  *)   SUITE=stable  ;;
esac

mkdir -p build/deb/conf

cat > build/deb/conf/distributions <<-EOF
	Origin: OpenBao - Official
	Label: OpenBao
	Suite: stable
	Codename: stable
	Architectures: amd64 arm64 armhf ppc64el riscv64 s390x
	Components: main
	Description: Official APT repository for OpenBao releases
	SignWith: ${GPG_FINGERPRINT}
	Limit: 0

	Origin: OpenBao - Official
	Label: OpenBao
	Suite: testing
	Codename: testing
	Architectures: amd64 arm64 armhf ppc64el riscv64 s390x
	Components: main
	Description: Official APT repository for OpenBao pre-releases
	SignWith: ${GPG_FINGERPRINT}
	Limit: 0
EOF

reprepro -b build/deb includedeb "$SUITE" dist/*.deb
