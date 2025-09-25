#!/bin/bash

modules=$(find . -name go.mod -mindepth 2)

grep '^	' go.mod | while read line; do
	pkg="$(awk '{print $1}' <<< "$line")"
	version="$(awk '{print $2}' <<< "$line")"

	while read go_mod; do
		dir="$(dirname "$go_mod")"
		if grep -q "^	$pkg " "$go_mod" && grep "$pkg" "$go_mod" | grep -qv "$pkg $version"; then
			( cd "$dir" && go get "$pkg"@"$version" )
		fi
	done <<< "$modules"
done

make tidy-all
