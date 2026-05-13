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
    community: [
        "index",
        {
            type: 'link',
            label: 'GitHub Discussions',
            href: "https://github.com/openbao/openbao/discussions",
        },
        {
            type: 'link',
            label: 'Zulip Chat Server',
            href: "https://linuxfoundation.zulipchat.com/",
        },
        {
            "Release Notes": [
                "release-notes/index",
                "release-notes/2-5-0",
                "release-notes/2-4-0",
                "release-notes/2-3-0",
                "release-notes/2-2-0",
                "release-notes/2-1-0",
                "release-notes/2-0-0",
            ],
            "Deprecation Notices": [
                "deprecation/index",
                "deprecation/faq",
                "deprecation/unauthed-rekey",
            ],
        },
        "known-issues",
        {
            Contributing: [
                "contributing/index",
                "contributing/code-organization",
                "contributing/packaging",
            ],
            Policies: [
                "policies/index",
                "policies/brand",
                "policies/deprecation",
                "policies/migration",
                "policies/plugins",
                "policies/release",
                "policies/support",
                "policies/osps-baseline",
                "policies/cve",
                "policies/repo-setup",
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
                "rfcs/auto-unseal-plugins",
                "rfcs/inline-auth",
                "rfcs/authenticated-rekey",
                "rfcs/self-init",
                "rfcs/namespace-sealing",
                "rfcs/external-keys",
                "rfcs/config-audit-devices",
                "rfcs/opentelemetry",
                "rfcs/efficient-search-components",
                "rfcs/emergency-seal",
                {
                    "UI/UX": ["rfcs/web-ui-modernization"],
                },
                {
                    "Horizontal Scalability": [
                        "rfcs/standby-nodes-handle-read-requests",
                    ],
                },
                "rfcs/config-plugins",
                "rfcs/postgresql",
                "rfcs/invalidation",
            ],
        },
        {
            type: 'link',
            label: 'Charter',
            href: "https://github.com/openbao/openbao/blob/main/CHARTER.md",
        },
    ],
};

export default sidebars;
