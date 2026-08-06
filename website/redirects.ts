export const redirects = [
    {
        from: "/api-docs/system/rotate-config",
        to: "/docs/api/system/rotate/keyring-config",
    },
    // Add unversioned variants of these redirects once 2.7.0 is cut.
    {
        from: "/docs/next/upgrading/",
        to: "/docs/next/guides/upgrade/",
    },
    {
        from: "/docs/next/upgrading/ha-upgrade",
        to: "/docs/next/guides/upgrade/ha",
    },
    {
        from: "/docs/next/upgrading/plugins-upgrade",
        to: "/docs/next/guides/upgrade/plugins",
    },
];

export function createRedirects(existingPath: string) {
    if (existingPath.includes('/community/') && existingPath !== '/community/') {
        return [
            existingPath.replace('/community/', '/docs/'),
            existingPath.replace('/community/', '/docs/next/'),
            existingPath.replace('/community/', '/docs/2.5.x/'),
            existingPath.replace('/community/', '/docs/2.4.x/'),
            existingPath.replace('/community/', '/docs/2.3.x/'),
        ];
    }

    if (existingPath.includes('/docs/api/')) {
        return [
            existingPath.replace('/docs/api/', '/api-docs/'),
            existingPath.replace('/docs/next/api/', '/api-docs/next/'),
            existingPath.replace('/docs/2.6.x/api/', '/api-docs/2.6.x/'),
            existingPath.replace('/docs/2.5.x/api/', '/api-docs/2.5.x/'),
            existingPath.replace('/docs/2.4.x/api/', '/api-docs/2.4.x/'),
        ];
    }

    if (existingPath.includes('/docs/api/secret/')) {
        return [
            existingPath.replace('/docs/api/secret/', '/docs/api/secrets/'),
            existingPath.replace('/docs/api/secret/', '/api-docs/secrets/'),
        ];
    }

    if (existingPath.includes('/docs/secrets/')) {
        return [
            existingPath.replace('/docs/secrets/', '/docs/secret/'),
        ];
    }

    return undefined;
};
