#!/usr/bin/env bash

# Run this script from the main branch targeting a release branch checkout
# (via path in argument) to automatically fix dependency vulnerabilities on the
# release branch by backporting the version that the dependency is at on the
# main branch. If a vulnerable version is still present on the main branch, this
# script will skip it and complain instead.

set -euo pipefail

release_dir="${1:-}"

if [[ -z "$release_dir" ]]; then
	echo "Usage: $0 /path/to/release/branch/checkout" 1>&2
	exit 1
fi

tools=$(realpath "$0/../../tools/go.mod")

# This is a cache of versions we've complained we can't bump to yet (because
# they haven't been upgraded on main), so we don't complain twice.
declare -A complaints

for go_mod in go.mod sdk/go.mod api/go.mod; do
  mod_dir=$(dirname "$release_dir/$go_mod")

  echo "$0: checking $go_mod"

  # When vulncheck finds distinct vulnerabilities affecting the same module,
  # it may suggest several fixed versions depending on the versions that each
  # vulnerability was fixed in respectively. Group suggested versions by module
  # and sort for the best one later on.
  bumps=$(
    env -C "$mod_dir" go tool -modfile="$tools" govulncheck -scan=package -format=json ./... \
    | jq -sc '
      map(
        .finding
        | select(.fixed_version != null)
        | { module: .trace[0].module, fixed_version }
      )
      | group_by(.module)
      | map({
          module: .[0].module,
          versions: map(.fixed_version) | unique,
      })
      | .[]'
  )

  if [[ -z "$bumps" ]]; then
    continue
  fi

  # Get dependency versions on the main (current) branch.
  main=$(go mod edit -modfile="$go_mod" -json | jq '.Require | .[]')

  # Track if we actually carry out a bump so we can skip sync-deps if nothing
  # happened.
  bumped=false

  while read -r bump; do
    module=$(jq -r '.module' <<< "$bump")
    fixed_versions=$(jq -r '.versions[]' <<< "$bump")
    version_on_main=$(jq -r --argjson bump "$bump" 'select(.Path == $bump.module) | .Version' <<< "$main")

    # Select the latest version out of (fixed_versions..., version_on_main).
    # Notably, version_on_main may be empty, in which case we fall back to
    # bumping to the earliest fixed version.
    later_version=$(printf '%s\n%s' "$fixed_versions" "$version_on_main" | sort -rV | head -n 1)

    if [[ "$later_version" == "$version_on_main" ]]; then
      bumped=true
      env -C "$mod_dir" go get "${module}@${version_on_main}"
    else
      target="${module}@${later_version}"

      if [[ -v "complaints[$target]" ]]; then
        continue
      else
        complaints["$target"]=1
      fi

      echo "$0: want to bump ${go_mod} to ${target}, but main is behind at ${version_on_main} !!!"
    fi
  done <<< "$bumps"

  if [[ "$bumped" == true ]]; then
    # Run sync-deps after changing any module so updates propagate and have a
    # chance to preemptively address vulnerabilities in the next module. For
    # example, addressing a vulnerability in the main module (which is scheduled
    # first) will lead to resolving them in sdk/ and api/ in 99% of cases.
    env -C "$release_dir" ./scripts/sync-deps.sh > /dev/null
  fi
done
