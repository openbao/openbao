#!/usr/bin/env bash

##
## Usage: echo ...github-autogen-whats-changed... | ./whats-changed.sh
##
## Then validate each "bad format" line and adjust as necessary.
##

GITHUB_REPO_API="${GITHUB_REPO_API:-https://api.github.com/repos/openbao/openbao/pulls/}"

while IFS= read -r line; do
	if	! grep -q '^\*' <<< "$line"; then
		echo "$line <!-- skip -->"
		continue
	elif ! grep -q '(#[0-9]*) by @' <<< "$line"; then
		echo "$line <!-- bad format -->"
		continue
	fi

	pr_number="$(grep -o '(#[0-9]*) by @' <<< "$line" | grep -o '[0-9]*')"
	pull_url="$GITHUB_REPO_API$pr_number"
	pull_info="$(curl --silent -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2026-03-10" "$pull_url")"
	author="$(jq -r .user.login <<< "$pull_info")"
	revised="$(sed 's/(#'"$pr_number"') by @/(#'"$pr_number"' by @'"$author"') backported by @/g' <<< "$line")"

	echo "$revised <!-- revised -->"
done < /dev/stdin
