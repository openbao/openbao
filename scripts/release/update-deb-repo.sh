#!/usr/bin/env bash

# This script updates a Debian package repository under build/ based on .deb
# packages available under dist/. The repository does not need to exist yet.

set -euo pipefail

mkdir -p build/deb/conf

cat > build/deb/conf/distributions <<-EOF
	Origin: OpenBao - Official
	Label: OpenBao
	Suite: stable
	Codename: stable
	Architectures: amd64 arm64 armhf ppc64el riscv64 s390x
	Components: main
	Description: Official APT repository for OpenBao
	SignWith: ${GPG_FINGERPRINT}
	Limit: 0
EOF

reprepro -b build/deb includedeb stable dist/*.deb
