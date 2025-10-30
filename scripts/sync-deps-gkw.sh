#!/bin/bash

grep '^	' go.mod | while read line; do
	pkg="$(awk '{print $1}' <<< "$line")"
	version="$(awk '{print $2}' <<< "$line")"

	(
		cd "$GO_KMS_WRAPPING"
		find . -name go.mod | while read gkw_mod; do
			dir="$(dirname "$gkw_mod")"
			if grep -q "^	$pkg" "$gkw_mod" && grep "$pkg" "$gkw_mod" | grep -qv "$pkg $version"; then
	  		( cd "$dir" && go get "$pkg"@"$version" )
			fi
	  done
	)
done

cd "$GO_KMS_WRAPPING" && make tidy-all
