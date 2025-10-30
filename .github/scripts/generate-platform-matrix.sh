#!/usr/bin/env bash
# generate-platform-matrix.sh, derive CI matrix from GoReleaser configs.
# Uses yq to parse GoReleaser configs.
# Usage: ./generate-platform-matrix.sh [mandatory|pending|all]

set -euo pipefail

SCOPE=${1:-mandatory}

# Helper: map goos/goarch → GitHub runner label
map_os() {
  local goos=$1 arch=$2
  case "$goos" in
    linux)   echo "ubuntu-latest";;
    windows) echo "windows-latest${arch:+}";;
    darwin)
      if [[ "$arch" == "arm64" ]]; then
        echo "macos-latest-arm64"  # GitHub's Apple-silicon runners
      else
        echo "macos-latest"
      fi
      ;;
    *) echo "ubuntu-latest";;
  esac
}

collect_pairs() {
  local file=$1
  # Using yq: iterate over builds, expand arrays → print goos|goarch lines
  yq -r '.builds[] | (.goos[]?) as $g | (.goarch[]?) as $a | "\($g)|\($a)"' "$file" 2>/dev/null || true
}

if ! command -v yq >/dev/null 2>&1; then
  echo "yq is required but not installed" >&2
  exit 1
fi

pairs=$( (collect_pairs goreleaser.linux.yaml; collect_pairs goreleaser.other.yaml) | sort -u )
if [[ -z "$pairs" ]]; then
  echo "Failed to derive platform pairs from GoReleaser configs" >&2
  exit 1
fi

json="$(echo "$pairs" | awk -F'|' '
{
  goos=$1; arch=$2;
  
  # Filter out invalid combinations based on GoReleaser ignore rules
  if (goos=="darwin") {
    # darwin only supports amd64 and arm64
    if (arch!="amd64" && arch!="arm64") next;
    runner="macos-latest";
  } else if (goos=="windows") {
    # windows only supports amd64 and arm64
    if (arch!="amd64" && arch!="arm64") next;
    runner="windows-latest";
  } else if (goos=="linux") {
    # linux supports: amd64, arm, arm64, ppc64le, riscv64, s390x
    runner="ubuntu-latest";
  } else if (goos=="freebsd") {
    # freebsd supports: amd64, arm, arm64, riscv64
    if (arch!="amd64" && arch!="arm" && arch!="arm64" && arch!="riscv64") next;
    runner="ubuntu-latest";
  } else if (goos=="illumos") {
    # illumos supports: amd64
    if (arch!="amd64") next;
    runner="ubuntu-latest";
  } else if (goos=="netbsd") {
    # netbsd supports: amd64, arm, arm64
    if (arch!="amd64" && arch!="arm" && arch!="arm64") next;
    runner="ubuntu-latest";
  } else if (goos=="openbsd") {
    # openbsd supports: amd64, arm, arm64
    if (arch!="amd64" && arch!="arm" && arch!="arm64") next;
    runner="ubuntu-latest";
  } else {
    # Map other OSes to ubuntu runner; cross-compile only
    runner="ubuntu-latest";
  }
  
  # Determine if this platform should use Docker buildx (exotic archs we cannot compile natively)
  buildx = "false"
  if (arch == "riscv64" || arch == "s390x" || arch == "ppc64" || arch == "ppc64le") {
    buildx = "true"
  } else if (goos != "linux" && goos != "windows" && goos != "darwin") {
    buildx = "true"
  }

  printf "{\"os\":\"%s\",\"goos\":\"%s\",\"goarch\":\"%s\",\"buildx\":%s}\n", runner, goos, arch, buildx;
}' | jq -s .)"

# Partition into scopes
mandatory_jq='map(select((.goos=="linux" and .goarch=="amd64") or (.goos=="windows" and .goarch=="amd64") or (.goos=="darwin" and (.goarch=="amd64" or .goarch=="arm64"))))'
pending_jq='map(select((.goos=="linux" and .goarch=="arm64") or (.goos=="windows" and .goarch=="arm64")))'

case "$SCOPE" in
  mandatory)
    echo "$json" | jq -c "$mandatory_jq"
    ;;
  pending)
    echo "$json" | jq -c "$pending_jq"
    ;;
  all)
    echo "$json" | jq -c .
    ;;
  *)
    echo "Usage: $0 [mandatory|pending|all]" >&2
    exit 1
    ;;
esac 