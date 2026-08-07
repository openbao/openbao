#!/bin/bash

for entry in ../changelog/*.txt; do
  echo "Checking $entry..."
  ./changelog.sh "$entry"
  if (( $? != 0 )); then
    exit 1
  fi

  echo ""
  echo ""
  echo ""
done
