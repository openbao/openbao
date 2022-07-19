FROM docker.mirror.hashicorp.services/hashicorp/vault-enterprise:1.10.3-ent as enterprise

# Don't use `kubernetes` as plugin name to ensure we don't silently fall back to
# the built-in kubernetes secrets plugin if something goes wrong.
COPY --chown=vault:vault vault-plugin-secrets-kubernetes /vault/plugin_directory/kubernetes-dev

FROM docker.mirror.hashicorp.services/hashicorp/vault:1.10.3

# Don't use `kubernetes` as plugin name to ensure we don't silently fall back to
# the built-in kubernetes secrets plugin if something goes wrong.
COPY --chown=vault:vault vault-plugin-secrets-kubernetes /vault/plugin_directory/kubernetes-dev
