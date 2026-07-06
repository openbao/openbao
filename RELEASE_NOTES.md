# sigilr release notes

**sigilr** is AppsCode's distribution of [OpenBao](https://openbao.org) — the
upstream server plus AppsCode-specific additions, improvements, and
enhancements. Versions track the OpenBao base they are cut from and carry a
`-sigilr.N` suffix (e.g. `v2.6.0-sigilr.1`, built on the OpenBao `v2.6.0` line).

Releases are cut by pushing a `v*-sigilr.*` tag on `main`; see
[Releasing](#releasing) below.

Each tagged release gets its own dated section here summarizing the
distribution-specific changes over upstream. Feature work lands in its own PR
and adds its own entry; this file starts by establishing the release pipeline.

---

## Unreleased

### Release engineering

Adds the distribution's release pipeline. This is build/publish tooling only —
no product or runtime code — so that tagging `v*-sigilr.*` produces signed-off,
reproducible artifacts under the `sigilr` org.

- **`goreleaser.sigilr.yaml`** — slim, secret-free GoReleaser config:
  - Cross-platform binaries — linux & darwin (`amd64`, `arm64`) and windows
    (`amd64`) — as `tar.gz`/`zip` archives plus `checksums.txt`. Binary stays
    `bao`; `-tags ui`; `CGO_ENABLED=0`.
  - Multi-arch container images (linux `amd64`+`arm64`) published to
    **`ghcr.io/<owner>/openbao`** only, tagged `:<version>` and `:latest`.
  - Deliberately excludes the upstream pipeline's deb/rpm, quay.io/docker.io
    mirrors, UBI/distroless variants, and GPG/cosign/APT/RPM/S3 steps — so a
    release needs **no configured secrets** beyond the built-in `GITHUB_TOKEN`.
- **`.github/workflows/release-sigilr.yml`** — tag-triggered release workflow.
  Fires on any pushed tag matching `v*-sigilr.*`, builds the UI
  (`make static-dist`), sets up Go/buildx/qemu, logs into GHCR, and runs
  GoReleaser against the config above. Publishes the GitHub release on the fork
  and pushes the images.
- **`RELEASE_NOTES.md`** — this file: the distribution release-notes doc and the
  [Releasing](#releasing) runbook.

### Artifacts a release produces
- Binaries (`tar.gz`/`zip`): linux & darwin (`amd64`, `arm64`), windows
  (`amd64`), plus `checksums.txt`.
- Container images: `ghcr.io/<owner>/openbao:<version>` and `:latest`
  (multi-arch: linux `amd64`, `arm64`).
- A GitHub release on `sigilr/openbao` with the above attached.

### Notes
- Versioning tracks the OpenBao base with a `-sigilr.N` suffix. The first tag,
  `v2.6.0-sigilr.1`, targets the OpenBao `v2.6.0` line (latest upstream tag
  `v2.6.0-beta20260622`), which is currently pre-GA upstream; move to a stable
  `v2.6.0` base once upstream releases it.
- Product features (e.g. the `bao relay` hub-and-spoke remote-database engine)
  ship in their own PRs and will add their own entry to the release's section
  before it is tagged.
- The first image push creates a **private** GHCR package; make it public in the
  org's package settings if anonymous pulls are wanted.

---

## Releasing

Releases are produced by `.github/workflows/release-sigilr.yml`, which fires on
any pushed tag matching `v*-sigilr.*` and runs `goreleaser.sigilr.yaml`.

```bash
# From an up-to-date main:
git checkout main && git pull

# Promote the "Unreleased" section to the version being cut, commit it, then tag:
git tag -s v2.6.0-sigilr.1 -m "sigilr v2.6.0-sigilr.1"
git push origin main
git push origin v2.6.0-sigilr.1     # <- this push triggers the release
```

The workflow builds the UI, cross-compiles the binaries, publishes the GitHub
release on `sigilr/openbao`, and pushes multi-arch images to
`ghcr.io/sigilr/openbao`. No signing/APT/RPM/S3 secrets are required.
