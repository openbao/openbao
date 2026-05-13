import { JSX } from "react";

const ARCHES = [
    "amd64",
    "arm64",
    "armhf",
    "armv7hl",
    "arm",
    "riscv64",
    "aarch64",
    "x86_64",
    "ppc64le",
    "s390x",
];

type ArchPackageMap = Record<string, string[]>;

interface Release {
    assets: {
        linux: {
            deb: ArchPackageMap;
            rpm: ArchPackageMap;
            pkg: ArchPackageMap;
            binary: ArchPackageMap;
            docker: ArchPackageMap;
        };
        darwin: { binary: ArchPackageMap };
        freebsd: { binary: ArchPackageMap };
        netbsd: { binary: ArchPackageMap };
        openbsd: { binary: ArchPackageMap };
        windows: { binary: ArchPackageMap };
    };
}

type Releases = Record<string, Release>;

interface GHRelease {
    tag_name: string;
    assets: GHAsset[];
}

interface GHAsset {
    browser_download_url: string;
}


const newArchPackageMap = (): ArchPackageMap => {
    const map: ArchPackageMap = {};
    for (const arch of ARCHES) {
        map[arch] = [];
    }
    map["<none>"] = [];
    return map;
}


const GetReleases = (response: unknown): Releases => {
    const releases = response as GHRelease[];
    const result: Releases = {};

    for (const r of releases) {
        const version = r.tag_name;
        const release: Release = {
            assets: {
                linux: {
                    deb: newArchPackageMap(),
                    rpm: newArchPackageMap(),
                    pkg: newArchPackageMap(),
                    binary: newArchPackageMap(),
                    docker: newArchPackageMap(),
                },
                darwin: { binary: newArchPackageMap() },
                freebsd: { binary: newArchPackageMap() },
                netbsd: { binary: newArchPackageMap() },
                openbsd: { binary: newArchPackageMap() },
                windows: { binary: newArchPackageMap() },
            },
        };

        for (const asset of r.assets) {
            const url = asset.browser_download_url;
            const urlLower = url.toLowerCase();
            const arch = AssetArchitecture(url);

            if (urlLower.includes("sbom") || urlLower.includes("checksums")) {
                continue;
            }

            if (urlLower.includes("windows")) {
                release.assets.windows.binary[arch].push(url);
            } else if (urlLower.includes("openbsd")) {
                release.assets.openbsd.binary[arch].push(url);
            } else if (urlLower.includes("netbsd")) {
                release.assets.netbsd.binary[arch].push(url);
            } else if (urlLower.includes("freebsd")) {
                release.assets.freebsd.binary[arch].push(url);
            } else if (urlLower.includes("darwin")) {
                release.assets.darwin.binary[arch].push(url);
            } else if (urlLower.includes("docker")) {
                release.assets.linux.docker[arch].push(url);
                continue;
            } else if (urlLower.includes(".rpm")) {
                release.assets.linux.rpm[arch].push(url);
                continue;
            } else if (urlLower.includes(".deb")) {
                release.assets.linux.deb[arch].push(url);
                continue;
            } else if (urlLower.includes(".pkg")) {
                release.assets.linux.pkg[arch].push(url);
                continue;
            } else if (urlLower.includes("linux")) {
                release.assets.linux.binary[arch].push(url);
            }
        }
        result[version] = release;
    }
    return result;
}

const AssetArchitecture = (url: string): string => {
    for (const arch of ARCHES) {
        if (url.includes(arch)) {
            return arch;
        }
    }
    return "<none>";
}

const OsPrettyPrint = (name: string): string => {
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
        default:
            return "";
    }
}


type ArchPackageMapApplicationLambda = () => JSX.Element;

const ArchPackageMapApply = (
    category: ArchPackageMap,
    lambda: ArchPackageMapApplicationLambda
): JSX.Element[] => {
    const result: JSX.Element[] = [];

    for (const arch of ARCHES) {
        if (arch in category) {
            result.push(lambda(category[arch], arch));
        }
    }

    return result;
};

export { ArchPackageMapApply, ArchPackageMap, ArchPackageMapApplicationLambda, GetReleases, OsPrettyPrint, AssetArchitecture }
