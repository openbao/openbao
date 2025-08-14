import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  // By default, Docusaurus generates a sidebar from the docs folder structure
  api: [
    "libraries",
    "relatedtools",
    {
      "Secret Engines": [
        "secret/index",
        "secret/cubbyhole",
        {
          Databases: [
            "secret/databases/index",
            "secret/databases/cassandra",
            "secret/databases/influxdb",
            "secret/databases/mysql-maria",
            "secret/databases/postgresql",
            "secret/databases/valkey",
          ],
          Identity: [
            "secret/identity/index",
            "secret/identity/entity",
            "secret/identity/entity-alias",
            "secret/identity/group",
            "secret/identity/group-alias",
            "secret/identity/tokens",
            "secret/identity/lookup",
            "secret/identity/oidc-provider",
            {
              MFA: [
                "secret/identity/mfa/index",
                "secret/identity/mfa/duo",
                "secret/identity/mfa/okta",
                "secret/identity/mfa/pingid",
                "secret/identity/mfa/totp",
                "secret/identity/mfa/login-enforcement",
              ],
            },
          ],
          "Key/Value": [
            "secret/kv/index",
            "secret/kv/kv-v1",
            "secret/kv/kv-v2",
          ],
        },
        "secret/kubernetes",
        "secret/ldap",
        "secret/pki",
        "secret/rabbitmq",
        "secret/ssh",
        "secret/totp",
        "secret/transit",
      ],
      "Auth Methods": [
        "auth/index",
        "auth/approle",
        "auth/jwt",
        "auth/kerberos",
        "auth/kubernetes",
        "auth/ldap",
        "auth/radius",
        "auth/cert",
        "auth/token",
        "auth/userpass",
      ],
      "System Backend": [
        "system/index",
        "system/audit",
        "system/audit-hash",
        "system/auth",
        "system/capabilities",
        "system/capabilities-accessor",
        "system/capabilities-self",
        "system/config-auditing",
        "system/config-cors",
        "system/config-state",
        "system/config-ui",
        "system/decode-token",
        "system/generate-recovery-token",
        "system/generate-root",
        "system/health",
        "system/host-info",
        "system/in-flight-req",
        "system/init",
        "system/internal-counters",
        {
          "sys/internal/inspect": [
            "system/inspect/index",
            "system/inspect/request",
            "system/inspect/router",
          ],
        },
        "system/internal-specs-openapi",
        "system/internal-ui-feature",
        "system/internal-ui-mounts",
        "system/internal-ui-namespaces",
        "system/internal-ui-resultant-acl",
        "system/key-status",
        "system/ha-status",
        "system/leader",
        "system/leases",
        "system/loggers",
        "system/metrics",
        "system/mfa-validate",
        "system/monitor",
        "system/mounts",
        "system/namespaces",
        "system/plugins-reload-backend",
        "system/plugins-catalog",
        "system/policy",
        "system/policies",
        "system/policies-password",
        "system/pprof",
        "system/quotas-config",
        "system/rate-limit-quotas",
        "system/raw",
        "system/rekey",
        "system/rekey-recovery-key",
        "system/remount",
        {
          "sys/rotate": [
            "system/rotate/index",
            "system/rotate/keyring",
            "system/rotate/keyring-config",
            "system/rotate/root",
            "system/rotate/init",
            "system/rotate/update",
            "system/rotate/verify",
            "system/rotate/backup",
          ],
        },
        "system/seal",
        "system/seal-status",
        "system/step-down",
        {
          "sys/storage": [
            "system/storage/index",
            "system/storage/raft",
            "system/storage/raftautopilot",
          ],
        },
        "system/tools",
        "system/unseal",
        "system/user-lockout",
        "system/version-history",
        "system/wrapping-lookup",
        "system/wrapping-rewrap",
        "system/wrapping-unwrap",
        "system/wrapping-wrap",
      ],
    },
  ],
};

export default sidebars;
