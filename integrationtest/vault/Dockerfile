FROM docker.mirror.hashicorp.services/hashicorp/vault:1.10.1

# Don't use `kubernetes` as plugin name to ensure we don't silently fall back to
# the built-in kubernetes secrets plugin if something goes wrong.
COPY --chown=vault:vault vault-plugin-secrets-kubernetes /vault/plugin_directory/kubernetes-dev
