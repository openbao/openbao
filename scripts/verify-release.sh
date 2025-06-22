#!/bin/bash

RELEASE_TAG="$1"

GITHUB_TOKEN="${GITHUB_TOKEN:-}"
OWNER="${OWNER:-openbao}"
REPO="${REPO:-openbao}"
TMPDIR="${TMPDIR:-/tmp}"
GPG_KEY_NAME="${GPG_KEY_NAME:-openbao-gpg-pub-20240618.asc}"

DOWNLOAD_FOLDER="${TMPDIR}/${OWNER}-${REPO}-${RELEASE_TAG}"

if [ ! -e "$DOWNLOAD_FOLDER" ]; then
  mkdir -p "$DOWNLOAD_FOLDER"
fi

release_cache="${TMPDIR}/${OWNER}-${REPO}-release-${RELEASE_TAG}.json"
release_api="https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/${RELEASE_TAG}"
bearer_header=""
if [ -n "$GITHUB_TOKEN" ]; then
  bearer_header="Authorization: Bearer $GITHUB_TOKEN"
fi

release_info=""
if [ -e "$release_cache" ]; then
  release_info="$(cat "$release_cache")"
else
  release_info="$(curl -sSL \
    -H "Accept: application/vnd.github+json" \
    -H "$bearer_header" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$release_api")"
  echo "$release_info" > "$release_cache"
fi

assets_count="$(jq '.assets | length' <<< "$release_info")"

for index in $(seq 0 $(( assets_count - 1 ))); do
  download_url="$(jq -r ".assets[$index].browser_download_url" <<< "$release_info")"
  download_file="$(basename "$download_url")"
  download_path="${DOWNLOAD_FOLDER}/${download_file}"

  if [ ! -e "$download_path" ]; then
    echo "Downloading $download_file..."
    curl -sSL "$download_url" --output "$download_path"
    sleep 2
  fi
done

if [ ! -e "${DOWNLOAD_FOLDER}/${GPG_KEY_NAME}" ]; then
  echo "Missing GPG file ($GPG_KEY_NAME); upload to release and rerun" 1>&2
  exit 1
fi

cd "$DOWNLOAD_FOLDER"

(
  set -euxo pipefail

  gpg2 --import "${GPG_KEY_NAME}"

  # First verify all GPG files
  for file in *; do
    gpg_file="${file}.gpgsig"
    if [ ! -e "$gpg_file" ]; then
      continue
    fi

    gpg2 --verify "$gpg_file" "$file"
  done

  # Then verify cosign signatures
  for file in *; do
    cosign_sig="${file}.sig"
    cosign_rawsig="${file}.rawsig"
    cosign_cert="${file}.pem"
    cosign_rawcert="${file}.rawpem"
    if [ ! -e "$cosign_sig" ] && [ ! -e "$cosign_cert" ]; then
      continue
    fi
    if [ ! -e "$cosign_sig" ] || [ ! -e "$cosign_cert" ]; then
      echo "$file is missing either $cosign_sig or $cosign_cert" 1>&2
      exit 1
    fi

    # See https://openbao.org/docs/install/#cosign-and-rekor
    # Newer releases already have the certificate available.
    base64 -d < "$cosign_sig" > "$cosign_rawsig"
    base64 -d < "$cosign_cert" > "$cosign_rawcert"
    openssl pkeyutl -verify -certin -inkey "$cosign_rawcert" -sigfile "$cosign_rawsig" -in "$file" -rawin
  done


  # Lastly verify checksums
  sha256sum --check checksums-*.txt
)
