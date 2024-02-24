#!/bin/sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


TOC="## Table of Contents"
FIRST="## Community Support"

tmpfile=$(dirname $0)/tmp.md

# prints everything up to TOC header
sed -n "0,/^${TOC}/p" < README.md > $tmpfile
# print the TOC
printf "\n" >> $tmpfile
cat README.md \
    `# strip out code blocks` \
    | sed -e '/```/ r pf' -e '/```/,/```/d' \
    `# pull out header lines, skipping first 2` \
    | grep "^#" \
    | tail -n +3 \
    `# strip out bad characters` \
    | tr -d '`' \
    `# format as [header](link)` \
    | sed -e 's/# \([a-zA-Z0-9. -]\+\)/- [\1](#\L\1)/' \
    `# replace spaces in '(link)' with dashes` \
    | awk -F'(' '{for(i=2;i<=NF;i++)if(i==2)gsub(" ","-",$i);}1' OFS='(' \
    `# remove dots '.' in '(link)'` \
    | awk -F'(' '{for(i=2;i<=NF;i++)if(i==2)gsub("\.","",$i);}1' OFS='(' \
    `# convert header to indention (brute force)` \
    | sed -e 's/^####/      /' \
    | sed -e 's/^###/    /' \
    | sed -e 's/^##/  /' \
    | sed -e 's/^#//' \
    >> $tmpfile
printf "\n\n" >> $tmpfile
# print the rest of the file, starting with FIRST header
sed -n "/^${FIRST}/,$ p" < README.md >> $tmpfile
# copy over original
mv $tmpfile README.md
