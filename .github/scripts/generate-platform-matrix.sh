#!/usr/bin/env bash
# generate-platform-matrix.sh derives CI targets directly from the GoReleaser build
# definitions. The output is a JSON array of build targets, optionally filtered to
# the mandatory native release platforms.
# Usage: ./.github/scripts/generate-platform-matrix.sh [mandatory|all]

set -euo pipefail

SCOPE=${1:-mandatory}

case "$SCOPE" in
  mandatory|all)
    ;;
  *)
    echo "Usage: $0 [mandatory|all]" >&2
    exit 1
    ;;
esac

if ! command -v yq >/dev/null 2>&1; then
  echo "yq is required but not installed" >&2
  exit 1
fi

jq_filter=$(cat <<'JQ'
def candidate_is_ignored($candidate; $rules):
  any(($rules // [])[]; (
    ((has("goos") | not) or .goos == $candidate.goos) and
    ((has("goarch") | not) or .goarch == $candidate.goarch) and
    ((has("goarm") | not) or (.goarm | tostring) == (($candidate.goarm // "") | tostring))
  ));

def runner_for:
  if .goos == "linux" and .goarch == "amd64" then
    "ubuntu-24.04"
  elif .goos == "linux" and .goarch == "arm64" then
    "ubuntu-24.04-arm"
  elif .goos == "windows" and .goarch == "amd64" then
    "windows-2025"
  elif .goos == "windows" and .goarch == "arm64" then
    "windows-11-arm"
  elif .goos == "darwin" and .goarch == "amd64" then
    "macos-15-intel"
  elif .goos == "darwin" and .goarch == "arm64" then
    "macos-15"
  else
    "ubuntu-24.04"
  end;

def mandatory_target:
  (.goos == "linux" and (.goarch == "amd64" or .goarch == "arm64")) or
  (.goos == "windows" and (.goarch == "amd64" or .goarch == "arm64")) or
  (.goos == "darwin" and (.goarch == "amd64" or .goarch == "arm64"));

def testable_target:
  mandatory_target;

def build_tags_for($build):
  if (($build.tags // []) | length) > 0 then
    ($build.tags | join(","))
  else
    "openbao"
  end;

def binary_tests_target:
  testable_target and (
    (.goos == "linux" and (.goarch == "amd64" or .goarch == "arm64")) or
    (.goos == "windows" and .goarch == "amd64")
  );

def buildx_target:
  .goos == "linux" and (
    .goarch == "ppc64le" or
    .goarch == "riscv64" or
    .goarch == "s390x"
  );

map(
  . as $build
  | [
      ($build.goos // [])[] as $goos
      | ($build.goarch // [])[] as $goarch
      | (if $goarch == "arm" then ($build.goarm // [null]) else [null] end)[] as $goarm
      | (
          {
            goos: $goos,
            goarch: $goarch,
            build_tags: build_tags_for($build)
          }
          + if $goarm != null then {goarm: ($goarm | tostring)} else {} end
        )
    ]
  | map(select(candidate_is_ignored(.; $build.ignore) | not))
)
| add
| unique_by([.goos, .goarch, (.goarm // "")])
| sort_by(.goos, .goarch, (.goarm // ""))
| map(
    . + {
      runner: runner_for,
      buildx: buildx_target,
      testable: testable_target,
      mandatory: mandatory_target,
      binary_tests: binary_tests_target
    }
  )
| if $scope == "mandatory" then
    map(select(.mandatory))
  else
    .
  end
JQ
)

json="$(
  {
    yq '.builds[]' goreleaser.linux.yaml
    yq '.builds[]' goreleaser.other.yaml
  } | jq -cs --arg scope "$SCOPE" "$jq_filter"
)"

if [[ -z "$json" || "$json" == "null" ]]; then
  echo "Failed to derive platform matrix from GoReleaser configs" >&2
  exit 1
fi

echo "$json" | jq -c .
