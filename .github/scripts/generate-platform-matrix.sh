#!/usr/bin/env bash
# generate-platform-matrix.sh filters the static CI platform matrix.
# Usage: ./.github/scripts/generate-platform-matrix.sh [mandatory|all]

set -euo pipefail

SCOPE=${1:-mandatory}
MATRIX_FILE=".github/platform-matrix.json"

case "$SCOPE" in
  mandatory|all)
    ;;
  *)
    echo "Usage: $0 [mandatory|all]" >&2
    exit 1
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not installed" >&2
  exit 1
fi

if [[ ! -f "$MATRIX_FILE" ]]; then
  echo "CI platform matrix file not found: $MATRIX_FILE" >&2
  exit 1
fi

jq -c --arg scope "$SCOPE" '
  .targets as $targets
  | (if $scope == "mandatory" then $targets | map(select(.mandatory)) else $targets end) as $build
  | {
      build: $build,
      test: ($build | map(select(.testable)))
    }
' "$MATRIX_FILE"
