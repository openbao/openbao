import Tabs from "@theme/Tabs";
import TabItem from "@theme/TabItem";

const arches: string[] = ["amd64", "arm64", "armhf", "armv7hl", "arm", "riscv64", "aarch64", "x86_64", "ppc64le", "s390x"];

interface ArchPackageMap {
    [key: string]: string[];
}

interface Release {
    assets: {
        linux: {
            deb: ArchPackageMap;
            rpm: ArchPackageMap;
            pkg: ArchPackageMap;
            binary: ArchPackageMap;
            docker: ArchPackageMap;
        };
        hsm: {
            deb: ArchPackageMap;
            rpm: ArchPackageMap;
            pkg: ArchPackageMap;
            binary: ArchPackageMap;
            docker: ArchPackageMap;
        };
        darwin: {
            binary: ArchPackageMap;
        };
        freebsd: {
            binary: ArchPackageMap;
        };
        netbsd: {
            binary: ArchPackageMap;
        };
        openbsd: {
            binary: ArchPackageMap;
        };
        windows: {
            binary: ArchPackageMap;
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

function NewArchPackageMap(): ArchPackageMap {
    let x: ArchPackageMap = {};
    for (let arch of arches) {
        x[arch] = [];
    }
    x["<none>"] = [];
    return x;
}

export function GetReleases(response): Releases {
    const releases: GHRelease[] = response as GHRelease[];
    const result: Releases = {};

    releases.forEach((r) => {
        const version = r.tag_name;

        var release = {
            assets: {
                linux: {
                    deb: NewArchPackageMap(),
                    rpm: NewArchPackageMap(),
                    pkg: NewArchPackageMap(),
                    binary: NewArchPackageMap(),
                    docker: NewArchPackageMap(),
                },
                hsm: {
                    deb: NewArchPackageMap(),
                    rpm: NewArchPackageMap(),
                    pkg: NewArchPackageMap(),
                    binary: NewArchPackageMap(),
                    docker: NewArchPackageMap(),
                },
                darwin: {
                    binary: NewArchPackageMap(),
                },
                freebsd: {
                    binary: NewArchPackageMap(),
                },
                netbsd: {
                    binary: NewArchPackageMap(),
                },
                openbsd: {
                    binary: NewArchPackageMap(),
                },
                windows: {
                    binary: NewArchPackageMap(),
                },
            },
        } as Release;
        for (var a of r.assets) {
            let arch = AssetArchitecture(a.browser_download_url);
            if (a.browser_download_url.toLowerCase().includes("sbom")) {
                // skip SBOM release assets, they are not relevant for the
                // download page
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes("checksums")) {
                // skip checksum files, they are not relevant for the
                // download page
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes("windows")) {
                release.assets.windows.binary[arch].push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("openbsd")) {
                release.assets.openbsd.binary[arch].push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("netbsd")) {
                release.assets.netbsd.binary[arch].push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("freebsd")) {
                release.assets.freebsd.binary[arch].push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("darwin")) {
                release.assets.darwin.binary[arch].push(a.browser_download_url);
            }
            if (a.browser_download_url.toLowerCase().includes("hsm")) {
                if (a.browser_download_url.toLowerCase().includes("docker")) {
                    release.assets.hsm.docker[arch].push(a.browser_download_url);
                    // docker urls also contain "hsm", so contiune if we find it
                    continue;
                }
                if (a.browser_download_url.toLowerCase().includes(".rpm")) {
                    release.assets.hsm.rpm[arch].push(a.browser_download_url);
                    // rpm urls also contain "hsm", so contiune if we find it
                    continue;
                }
                if (a.browser_download_url.toLowerCase().includes(".deb")) {
                    release.assets.hsm.deb[arch].push(a.browser_download_url);
                    // deb urls also contain "hsm", so contiune if we find it
                    continue;
                }
                if (a.browser_download_url.toLowerCase().includes(".pkg")) {
                    release.assets.hsm.pkg[arch].push(a.browser_download_url);
                    // pkg urls also contain "hsm", so contiune if we find it
                    continue;
                }
                if (a.browser_download_url.toLowerCase().includes("hsm")) {
                    release.assets.hsm.binary[arch].push(a.browser_download_url);
                }
                // Unknown item, continue because we don't want to match Linux
                // as well.
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes("docker")) {
                release.assets.linux.docker[arch].push(a.browser_download_url);
                // docker urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes(".rpm")) {
                release.assets.linux.rpm[arch].push(a.browser_download_url);
                // rpm urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes(".deb")) {
                release.assets.linux.deb[arch].push(a.browser_download_url);
                // deb urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes(".pkg")) {
                release.assets.linux.pkg[arch].push(a.browser_download_url);
                // pkg urls also contain "linux", so contiune if we find it
                continue;
            }
            if (a.browser_download_url.toLowerCase().includes("linux")) {
                release.assets.linux.binary[arch].push(a.browser_download_url);
            }
        }
        result[version] = release;
    });

    return result;
}

export function AssetArchitecture(url: string): string {
    for (let arch of arches) {
        if (url.includes(arch)) {
            return arch;
        }
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
        case "hsm":
            return "HSM for Linux";
    }
    return "";
}

interface ArchPackageMapApplicationLambda {
    (value: string, key: string): JSX.Element;
}

export function ArchPackageMapApply(category: ArchPackageMap, lambda: ArchPackageMapApplicationLambda): JSX.Element {
    var result: JSX.Element[] = [];
    for (let arch of arches) {
        if (arch in category) {
            const item = lambda(category[arch], arch);
            if (item !== null && item !== undefined) {
                result.push(
                    <TabItem value={ arch }>
                        { item }
                    </TabItem>
                );
            }
        }
    }

    if (result.length > 0) {
        return (
            <Tabs>
                { result }
            </Tabs>
        );
    }

    return null;
}
