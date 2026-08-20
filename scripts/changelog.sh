#!/usr/bin/env bash

# Adjust this and CONTRIBUTING.md when adding new types
allowed_types=("bug" "feature" "change" "improvement" "deprecation" "security")

function validate() {
  preamble="$1"
  content="$2"
  postscript="$3"

  if ! grep -q '^```' <<< "$preamble"; then
    echo "Expected changelog entry to be in a code block."
    echo 'Start each entry with "```release-note:<type>" and end with "```" on their own lines.'
    return 1
  fi

  if ! grep -q '^```release-note:' <<< "$preamble" ; then
    echo "Expected annotation 'release-note:<type>' on changelog"
    return 1
  fi

  category="$(sed 's/^```release-note://g' <<< "$preamble")"
  found=false
  for allowed in "${allowed_types[@]}"; do
    if [[ "$category" == "$allowed" ]]; then
      found=true
      break
    fi
  done

  if [[ "$found" != true ]]; then
    echo "Expected category (\"$category\") to be one of the following types:"
    echo "${allowed_types[@]}"
    return 1
  fi

  lines="$(wc -l <<< "$content\n")"
  if (( lines > 1 )) && [[ "$category" != "feature" ]] && [[ "$category" != "deprecation" ]] && [[ "$category" != "change" ]]; then
    echo "Expected only a single-line changelog for entry of this category (\"$category\")."
    echo "Do not word-wrap entries."
    echo ""
    echo "Content:"
    echo "$content"
    return 1
  elif (( lines > 1 )); then
    # Ensure they're indented at least 2 spaces.
    index=0
    while IFS= read -r line; do
      index=$(( index + 1 ))
      if (( index == 1 )); then
        component="$(grep -o '^[^:]*:' <<< "$content")"

        if [[ "$category" != "feature" ]] && [[ "$category" != "deprecation" ]]; then
          # Component has to match [a-z/]*.
          if ! grep -q '^[a-z][a-z0-9/-]*\(, [a-z][a-z0-9/-]*\)*:' <<< "$component"; then
            echo 'Expected changelog component(s) of the form [a-z]+(/[a-z]*)'
            echo "Component: $component"
            return 1
          fi
        else
          if ! grep -q "^\*\*.*\*\*:" <<< "$component"; then
            echo 'Expected changelog component of the form \*\*.*\*\*'
            echo 'Features should be a bolded name.'
            echo "Component: $component"
            return 1
          fi
        fi
      fi

      if (( index > 1 )) && ! grep -q '^  ' <<< "$line"; then
        echo "Expected subsequent lines in multi-line changelog entry to be indented."
        echo "Line $index ($line) was not."
        echo ""
        echo "Content:"
        echo "$content"
        return 1
      fi
    done <<< "$content"
  else
    # Single line entries should be of the form:
    # <component: [a-z/]*>: [A-Z].*\.
    #
    # That is, have a component that is lower case and at most two parts,
    # and then have one or more full sentences afterwards. When the category
    # is feature or deprecation, we allow multi-part bold components. We
    # require bold for features but allow it for deprecations.
    component="$(grep -o '^[^:]*:' <<< "$content")"

    if [[ -z "$component" ]]; then
      echo 'Missing component on changelog entry!'
      if [[ "$category" != "feature" ]]; then
        echo 'Component should be of the form [a-z0-9-]+(/[a-z0-9-]*) and end with a colon.'
      else
        echo 'Component should be a bolded (enclosed in "**") name and end with a colon.'
      fi
      return 1
    fi

    if [[ "$category" != "feature" ]] && [[ "$category" != "deprecation" ]]; then
      # Component has to match [a-z/]*.
      if ! grep -q '^[a-z][a-z0-9/-]*\(, [a-z][a-z0-9/-]*\)*:' <<< "$component"; then
        echo 'Expected changelog component(s) of the form [a-z]+(/[a-z]*)'
        echo "Component: $component"
        return 1
      fi

      # Description has to be a sentence.
      description="$(sed 's$^'"$component"'[[:space:]]*$$g' <<< "$content")"
      if [[ -z "$description" ]]; then
        echo 'Expected non-empty description.'
        echo "Component: $component"
        return 1
      fi

      if ! grep -q '^[A-Z`].*[\.!?][[:space:]]*$' <<< "$description"; then
        echo 'Expected description to start with a capital letter and end with a punctuation mark.'
        echo "Description: $description"
        return 1
      fi
    fi

    if [[ "$category" == "feature" ]]; then
      if ! grep -q "^\*\*.*\*\*:" <<< "$component"; then
        echo 'Expected changelog component of the form \*\*.*\*\*'
        echo 'Features should be a bolded name.'
        echo "Component: $component"
        return 1
      fi
    fi
  fi

  if [[ "$category" == "security" ]]; then
    if ! grep -q '\(HCSEC-\|CVE-\|GHSA-\)' <<< "$content"; then
      echo 'Expected HCSEC, CVE, or GHSA reference for security issue.'
      return 1
    fi
  fi

  if ! grep -q '^```$' <<< "$postscript"; then
    echo 'Expected trailing code block (```) in postscript of changelog entry'
    echo "Postscript: ($postscript)"
    return 1
  fi
}

function main() {
  file="$1"
  if [[ -z "$file" ]]; then
    echo "Usage: $0 /path/to/changelog/file" 1>&2
    exit 1
  fi

  preamble=""
  content=""
  postscript=""

  while IFS= read -r line; do
    if [[ -z "$line" ]]; then
      continue
    fi

    if [[ -z "$preamble" ]]; then
      preamble="$line"
    elif grep -q '^```' <<< "$line"; then
      postscript="$line"

      validate "$preamble" "$content" "$postscript"
      if (( $? != 0 )); then
        return 1
      fi

      echo "Changelog entry $preamble OK in $file"

      preamble=""
      content=""
      postscript=""
    else
      if [[ -z "$content" ]]; then
        content="$line"
      else
        content="$content
$line"
      fi
    fi
  done < "$file"
}

main "$@"
if (( $? != 0 )); then
  echo ""
  echo "Changelog file $file is invalid!"
  echo "Check CONTRIBUTING.md for more information"

  exit 1
fi
