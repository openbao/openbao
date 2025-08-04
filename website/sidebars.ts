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
    docs: [
        "what-is-openbao",
        "use-cases",
        {
            "Getting Started": ["get-started/developer-qs"],
        },
        "browser-support",
        "install",
        {
            Internals: [
                "internals/index",
                "internals/architecture",
                "internals/high-availability",
                "internals/integrated-storage",
                "internals/security",
                {
                    Telemetry: [
                        "internals/telemetry/index",
                        "internals/telemetry/enable-telemetry",
                        {
                            "Metrics Reference": [
                                "internals/telemetry/metrics/index",
                                "internals/telemetry/metrics/core-system",
                                "internals/telemetry/metrics/audit",
                                "internals/telemetry/metrics/authn",
                                "internals/telemetry/metrics/availability",
                                "internals/telemetry/metrics/database",
                                "internals/telemetry/metrics/policy",
                                "internals/telemetry/metrics/raft",
                                "internals/telemetry/metrics/secrets",
                                "internals/telemetry/metrics/storage",
                                "internals/telemetry/metrics/all",
                            ],
                        },
                    ],
                },
                "internals/token",
                "internals/rotation",
                "internals/limits",
            ],
            Concepts: [
                "concepts/index",
                "concepts/dev-server",
                "concepts/seal",
                "concepts/lease",
                "concepts/auth",
                "concepts/tokens",
                "concepts/identity",
                "concepts/oidc-provider",
                "concepts/profiles",
                "concepts/response-wrapping",
                "concepts/policies",
                "concepts/password-policies",
                "concepts/username-templating",
                "concepts/ha",
                "concepts/storage",
                {
                    "Integrated Storage": [
                        "concepts/integrated-storage/index",
                        "concepts/integrated-storage/autopilot",
                    ],
                },
                "concepts/pgp-gpg-keybase",
                "concepts/recovery-mode",
                "concepts/resource-quotas",
                "concepts/transform",
                "concepts/mount-migration",
                "concepts/duration-format",
                "concepts/user-lockout",
            ],
            Guides: [
                {
                    Unsealing: [
                        {
                            "PKCS#11": [
                                "guides/unseal/pkcs11/securosys"
                            ]
                        }
                    ]
                }
            ],
            Configuration: [
                "configuration/index",
                "configuration/self-init",
                {
                    listener: [
                        "configuration/listener/index",
                        "configuration/listener/unix",
                        "configuration/listener/tcp",
                    ],
                    seal: [
                        "configuration/seal/index",
                        "configuration/seal/alicloudkms",
                        "configuration/seal/awskms",
                        "configuration/seal/azurekeyvault",
                        "configuration/seal/gcpckms",
                        "configuration/seal/kmip",
                        "configuration/seal/ocikms",
                        "configuration/seal/pkcs11",
                        "configuration/seal/static",
                        "configuration/seal/transit",
                    ],
                    service_registration: [
                        "configuration/service-registration/index",
                        "configuration/service-registration/kubernetes",
                    ],
                    storage: [
                        "configuration/storage/index",
                        "configuration/storage/filesystem",
                        "configuration/storage/in-memory",
                        "configuration/storage/raft",
                        "configuration/storage/postgresql",
                    ],
                },
                "configuration/telemetry",
                "configuration/ui",
                "configuration/user-lockout",
                "configuration/log-requests-level",
            ],
            "Commands (CLI)": [
                "commands/index",
                "commands/agent",
                {
                    audit: [
                        "commands/audit/index",
                        "commands/audit/disable",
                        "commands/audit/enable",
                        "commands/audit/list",
                    ],
                    auth: [
                        "commands/auth/index",
                        "commands/auth/disable",
                        "commands/auth/enable",
                        "commands/auth/help",
                        "commands/auth/list",
                        "commands/auth/move",
                        "commands/auth/tune",
                    ],
                },
                "commands/debug",
                "commands/delete",
                {
                    kv: [
                        "commands/kv/index",
                        "commands/kv/delete",
                        "commands/kv/destroy",
                        "commands/kv/enable-versioning",
                        "commands/kv/get",
                        "commands/kv/list",
                        "commands/kv/metadata",
                        "commands/kv/patch",
                        "commands/kv/put",
                        "commands/kv/rollback",
                        "commands/kv/undelete",
                    ],
                    lease: [
                        "commands/lease/index",
                        "commands/lease/lookup",
                        "commands/lease/renew",
                        "commands/lease/revoke",
                    ],
                },
                "commands/list",
                "commands/login",
                "commands/monitor",
                {
                    operator: [
                        "commands/operator/index",
                        "commands/operator/diagnose",
                        "commands/operator/generate-root",
                        "commands/operator/init",
                        "commands/operator/key-status",
                        "commands/operator/members",
                        "commands/operator/migrate",
                        "commands/operator/raft",
                        "commands/operator/rekey",
                        "commands/operator/rotate",
                        "commands/operator/rotate-keys",
                        "commands/operator/seal",
                        "commands/operator/step-down",
                        "commands/operator/unseal",
                        "commands/operator/validate-config",
                    ],
                },
                "commands/patch",
                "commands/path-help",
                {
                    pki: [
                        "commands/pki/index",
                        "commands/pki/health-check",
                        "commands/pki/verify-sign",
                        "commands/pki/list-intermediates",
                        "commands/pki/issue",
                        "commands/pki/reissue",
                    ],
                    plugin: [
                        "commands/plugin/index",
                        "commands/plugin/deregister",
                        "commands/plugin/info",
                        "commands/plugin/list",
                        "commands/plugin/register",
                        "commands/plugin/reload",
                    ],
                    policy: [
                        "commands/policy/index",
                        "commands/policy/delete",
                        "commands/policy/fmt",
                        "commands/policy/list",
                        "commands/policy/read",
                        "commands/policy/write",
                    ],
                },
                "commands/print",
                "commands/proxy",
                "commands/read",
                {
                    secrets: [
                        "commands/secrets/index",
                        "commands/secrets/disable",
                        "commands/secrets/enable",
                        "commands/secrets/list",
                        "commands/secrets/move",
                        "commands/secrets/tune",
                    ],
                },
                "commands/server",
                "commands/ssh",
                "commands/status",
                {
                    token: [
                        "commands/token/index",
                        "commands/token/capabilities",
                        "commands/token/create",
                        "commands/token/lookup",
                        "commands/token/renew",
                        "commands/token/revoke",
                    ],
                    transit: [
                        "commands/transit/index",
                        "commands/transit/import",
                    ],
                },
                "commands/unwrap",
                "commands/version",
                "commands/version-history",
                "commands/write",
                "commands/token-helper",
            ],
            "OpenBao Agent and Proxy": [
                "agent-and-proxy/index",
                {
                    "Auto-Auth": [
                        "agent-and-proxy/autoauth/index",
                        {
                            Methods: [
                                "agent-and-proxy/autoauth/methods/index",
                                "agent-and-proxy/autoauth/methods/approle",
                                "agent-and-proxy/autoauth/methods/cert",
                                "agent-and-proxy/autoauth/methods/jwt",
                                "agent-and-proxy/autoauth/methods/kerberos",
                                "agent-and-proxy/autoauth/methods/kubernetes",
                                "agent-and-proxy/autoauth/methods/token_file",
                            ],
                            Sinks: [
                                "agent-and-proxy/autoauth/sinks/index",
                                "agent-and-proxy/autoauth/sinks/file",
                            ],
                        },
                    ],
                    "OpenBao Proxy": [
                        "agent-and-proxy/proxy/index",
                        "agent-and-proxy/proxy/apiproxy",
                        {
                            Caching: [
                                "agent-and-proxy/proxy/caching/index",
                                {
                                    "Persistent Caches": [
                                        "agent-and-proxy/proxy/caching/persistent-caches/index",
                                        "agent-and-proxy/proxy/caching/persistent-caches/kubernetes",
                                    ],
                                },
                                "agent-and-proxy/proxy/versions",
                            ],
                        },
                    ],
                    "OpenBao Agent": [
                        "agent-and-proxy/agent/index",
                        "agent-and-proxy/agent/apiproxy",
                        {
                            Caching: [
                                "agent-and-proxy/agent/caching/index",
                                {
                                    "Persistent Caches": [
                                        "agent-and-proxy/agent/caching/persistent-caches/index",
                                        "agent-and-proxy/agent/caching/persistent-caches/kubernetes",
                                    ],
                                },
                            ],
                        },
                        "agent-and-proxy/agent/generate-config/index",
                        "agent-and-proxy/agent/process-supervisor",
                        "agent-and-proxy/agent/template",
                        "agent-and-proxy/agent/winsvc",
                        "agent-and-proxy/agent/versions",
                    ],
                },
            ],
            "Secret Engines": [
                "secrets/index",
                "secrets/cubbyhole",
                {
                    Databases: [
                        "secrets/databases/index",
                        "secrets/databases/cassandra",
                        "secrets/databases/custom",
                        "secrets/databases/influxdb",
                        "secrets/databases/mysql-maria",
                        "secrets/databases/postgresql",
                        "secrets/databases/valkey",
                    ],
                    Identity: [
                        "secrets/identity/index",
                        "secrets/identity/identity-token",
                        "secrets/identity/oidc-provider",
                    ],
                    "Key/Value": [
                        "secrets/kv/index",
                        "secrets/kv/kv-v1",
                        "secrets/kv/kv-v2",
                    ],
                },
                "secrets/kubernetes",
                "secrets/ldap",
                {
                    "PKI (Certificates)": [
                        "secrets/pki/index",
                        "secrets/pki/setup",
                        "secrets/pki/quick-start-root-ca",
                        "secrets/pki/quick-start-intermediate-ca",
                        "secrets/pki/considerations",
                        "secrets/pki/troubleshooting-acme",
                        "secrets/pki/rotation-primitives",
                    ],
                },
                "secrets/rabbitmq",
                {
                    SSH: [
                        "secrets/ssh/index",
                        "secrets/ssh/signed-ssh-certificates",
                        "secrets/ssh/one-time-ssh-passwords",
                    ],
                },
                "secrets/totp",
                {
                    Transit: [
                        "secrets/transit/index",
                        "secrets/transit/key-wrapping-guide",
                    ],
                },
            ],
            "Auth Methods": [
                "auth/index",
                "auth/approle",
                {
                    "JWT/OIDC": [
                        "auth/jwt/index",
                        {
                            "OIDC Providers": [
                                "auth/jwt/oidc-providers/index",
                                "auth/jwt/oidc-providers/auth0",
                                "auth/jwt/oidc-providers/azuread",
                                "auth/jwt/oidc-providers/forgerock",
                                "auth/jwt/oidc-providers/gitlab",
                                "auth/jwt/oidc-providers/google",
                                "auth/jwt/oidc-providers/ibmisam",
                                "auth/jwt/oidc-providers/keycloak",
                                "auth/jwt/oidc-providers/kubernetes",
                                "auth/jwt/oidc-providers/okta",
                                "auth/jwt/oidc-providers/secureauth",
                            ],
                        },
                    ],
                },
                "auth/kerberos",
                "auth/kubernetes",
                "auth/ldap",
                {
                    "Login MFA": ["auth/login-mfa/index", "auth/login-mfa/faq"],
                },
                "auth/radius",
                "auth/cert",
                "auth/token",
                "auth/userpass",
            ],
            "Audit Devices": [
                "audit/index",
                "audit/file",
                "audit/syslog",
                "audit/socket",
            ],
            Plugins: [
                "plugins/index",
                "plugins/plugin-architecture",
                "plugins/plugin-development",
                "plugins/plugin-authors-guide",
                "plugins/plugin-management",
            ],
            Platforms: [
                "platform/index",
                {
                    Kubernetes: [
                        "platform/k8s/index",
                        "platform/k8s/injector-csi",
                        {
                            "Helm Chart": [
                                "platform/k8s/helm/index",
                                "platform/k8s/helm/run",
                                "platform/k8s/helm/openshift",
                                "platform/k8s/helm/configuration",
                                "platform/k8s/helm/terraform",
                                {
                                    Examples: [
                                        "platform/k8s/helm/examples/index",
                                        "platform/k8s/helm/examples/development",
                                        "platform/k8s/helm/examples/standalone-load-balanced-ui",
                                        "platform/k8s/helm/examples/standalone-tls",
                                        "platform/k8s/helm/examples/standalone-audit",
                                        "platform/k8s/helm/examples/external",
                                        "platform/k8s/helm/examples/kubernetes-auth",
                                        "platform/k8s/helm/examples/ha-with-raft",
                                        "platform/k8s/helm/examples/ha-tls",
                                        "platform/k8s/helm/examples/injector-tls",
                                        "platform/k8s/helm/examples/injector-tls-cert-manager",
                                    ],
                                },
                            ],
                            "Agent Injector": [
                                "platform/k8s/injector/index",
                                "platform/k8s/injector/annotations",
                                "platform/k8s/injector/installation",
                                "platform/k8s/injector/examples",
                            ],
                            "Vault CSI Provider": [
                                "platform/k8s/csi/index",
                                "platform/k8s/csi/installation",
                                "platform/k8s/csi/configurations",
                                "platform/k8s/csi/examples",
                            ],
                            "Vault Secrets Operator": [
                                "platform/k8s/vso/index",
                                "platform/k8s/vso/installation",
                                {
                                    "Secret Sources": [
                                        "platform/k8s/vso/sources/index",
                                        "platform/k8s/vso/sources/vault",
                                        "platform/k8s/vso/sources/hvs",
                                    ],
                                },
                                "platform/k8s/vso/examples",
                                "platform/k8s/vso/helm",
                                "platform/k8s/vso/telemetry",
                                "platform/k8s/vso/openshift",
                                "platform/k8s/vso/api-reference",
                            ],
                        },
                    ],
                },
            ],
            "Upgrade Guides": [
                "upgrading/index",
                "upgrading/ha-upgrade",
                "upgrading/plugins",
            ],
            "Release Notes": [
                "release-notes/index",
                "release-notes/2-3-0",
                "release-notes/2-2-0",
                "release-notes/2-1-0",
                "release-notes/2-0-0",
            ],
        },
        "known-issues",
        {
            "Deprecation Notices": ["deprecation/index", "deprecation/faq", "deprecation/unauthed-rekey"],
            Policies: [
                "policies/index",
                "policies/brand",
                "policies/deprecation",
                "policies/migration",
                "policies/plugins",
                "policies/release",
                "policies/support",
                "policies/osps-baseline",
            ],
            Contributing: [
                "contributing/index",
                "contributing/code-organization",
                "contributing/packaging",
            ],
            RFCs: [
                "rfcs/index",
                "rfcs/paginated-lists",
                "rfcs/mlock-removal",
                "rfcs/signed-commits",
                "rfcs/transactions",
                "rfcs/split-mount-tables",
                "rfcs/scan-operation",
                "rfcs/acme-tls-listeners",
                "rfcs/acl-paginated-lists",
                "rfcs/ssh-ca-multi-issuer",
                "rfcs/cel-best-practices",
                "rfcs/cel-pki",
                "rfcs/cel-jwt",
                "rfcs/filtering-list",
                "rfcs/static-auto-unseal",
                "rfcs/inline-auth",
                "rfcs/authenticated-rekey",
                "rfcs/self-init",
                "rfcs/external-keys",
                {
                  "UI/UX": ["rfcs/web-ui-modernization"],
                },
            ],
            FAQ: ["faq/index", "deprecation/faq", "auth/login-mfa/faq"],
        },
        "glossary",
    ],
};

export default sidebars;
