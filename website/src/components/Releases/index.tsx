interface Release {
    assets: {
        linux: {
            deb: string[];
            rpm: string[];
            binary: string[];
            docker: string[];
        };
        darwin: {
            binary: string[];
        };
        freebsd: {
            binary: string[];
        };
        netbsd: {
            binary: string[];
        };
        openbsd: {
            binary: string[];
        };
        windows: {
            binary: string[];
        };
    };
}

interface Releases {
    [key: string]: Release;
}

interface GHRelease {
    tag_name: string;
    assets: GHAsset[];
}

interface GHAsset {
    browser_download_url: string;
}

export function GetReleases(response): Releases {
    const releases: GHRelease[] = response as GHRelease[];
    const result: Releases = {};

    releases.forEach((r) => {
        const version = r.tag_name;

        var release = {
            assets: {
                linux: {
                    deb: [],
                    rpm: [],
                    binary: [],
                    docker: [],
                },
                darwin: {
                    binary: [],
                },
                freebsd: {
                    binary: [],
                },
                netbsd: {
                    binary: [],
                },
                openbsd: {
                    binary: [],
                },
                windows: {
                    binary: [],
                },
            },
        } as Release;
        for (var a of r.assets) {
            if (a.browser_download_url.toLowerCase().includes("sbom")) {
                // skip SBOM release assets, they are not relevant for the
                // download page
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes(".sig")) {
                // skip signature release assets, they are not relevant for the
                // download page
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes("windows")) {
                release.assets.windows.binary.push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("openbsd")) {
                release.assets.openbsd.binary.push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("netbsd")) {
                release.assets.netbsd.binary.push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("freebsd")) {
                release.assets.freebsd.binary.push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("darwin")) {
                release.assets.darwin.binary.push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("docker")) {
                release.assets.linux.docker.push(a.browser_download_url);
                // docker urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes(".rpm")) {
                release.assets.linux.rpm.push(a.browser_download_url);
                // rpm urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes(".deb")) {
                release.assets.linux.deb.push(a.browser_download_url);
                // deb urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes("linux")) {
                release.assets.linux.binary.push(a.browser_download_url);
            }
        }
        result[version] = release;
    });

    return result;
}

export function AssetArchitecture(url: string): string {
    if (url.includes("amd64")) {
        return "amd64";
    }
    if (url.includes("arm64")) {
        return "arm64";
    }
    if (url.includes("armhf")) {
        return "armhf";
    }
    if (url.includes("armv7hl")) {
        return "armv7hl";
    }
    if (url.includes("arm")) {
        return "arm";
    }
    if (url.includes("riscv64")) {
        return "riscv64";
    }
    if (url.includes("aarch64")) {
        return "aarch64";
    }
    if (url.includes("x86_64")) {
        return "x86_64";
    }
    if (url.includes("ppc64le")) {
        return "ppc64le";
    }
    if (url.includes("s390x")) {
        return "s390x";
    }
    return "<none>";
}

export function OsPrettyPrint(name: string): string {
    switch (name) {
        case "linux":
            return "Linux";
        case "darwin":
            return "MacOS";
        case "freebsd":
            return "FreeBSD";
        case "openbsd":
            return "OpenBSD";
        case "netbsd":
            return "NetBSD";
        case "windows":
            return "Windows";
    }
    return "";
}
