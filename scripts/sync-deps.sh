#!/bin/bash

grep '^	' go.mod | while read line; do
	pkg="$(awk '{print $1}' <<< "$line")"
	version="$(awk '{print $2}' <<< "$line")"

	if grep -q "^	$pkg" api/go.mod && grep "$pkg" api/go.mod | grep -qv "$pkg $version"; then
	  ( cd api && go get "$pkg"@"$version" )
	fi

    if grep -q "^	$pkg" api/auth/approle/go.mod && grep "$pkg" api/auth/approle/go.mod | grep -qv "$pkg $version"; then
	  ( cd api/auth/approle && go get "$pkg"@"$version" )
	fi

    if grep -q "^	$pkg" api/auth/kubernetes/go.mod && grep "$pkg" api/auth/kubernetes/go.mod | grep -qv "$pkg $version"; then
	  ( cd api/auth/kubernetes && go get "$pkg"@"$version" )
	fi

    if grep -q "^	$pkg" api/auth/ldap/go.mod && grep "$pkg" api/auth/ldap/go.mod | grep -qv "$pkg $version"; then
	  ( cd api/auth/ldap && go get "$pkg"@"$version" )
    fi

    if grep -q "^	$pkg" api/auth/userpass/go.mod && grep "$pkg" api/auth/userpass/go.mod | grep -qv "$pkg $version"; then
	  ( cd api/auth/userpass && go get "$pkg"@"$version" )
	fi

	if grep -q "^	$pkg" sdk/go.mod && grep "$pkg" sdk/go.mod | grep -qv "$pkg $version"; then
	  ( cd sdk && go get "$pkg"@"$version" )
	fi
done

make tidy-all
