# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

FROM docker.mirror.hashicorp.services/hashicorp/vault:1.13.0

# Don't use `kubernetes` as plugin name to ensure we don't silently fall back to
# the built-in kubernetes auth plugin if something goes wrong.
COPY --chown=vault:vault vault-plugin-auth-kubernetes /vault/plugin_directory/kubernetes-dev
