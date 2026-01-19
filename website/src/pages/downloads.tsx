import React, { useState, useEffect, createContext, useContext } from "react";
import Layout from "@theme/Layout";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import styles from "./index.module.css";
import Tabs from "@theme/Tabs";
import TabItem from "@theme/TabItem";
import CodeBlock from "@theme/CodeBlock";
import {
    GetReleases,
    AssetArchitecture,
    OsPrettyPrint,
    ArchPackageMapApply,
} from "@site/src/components/Releases";

// Create a context
const OptionsContext = createContext(null);

// Provider component
const OptionsProvider = ({ children }) => {
    const [options, setOptions] = useState({});
    const [selectedItem, setSelectedItem] = useState("");

    useEffect(() => {
        // Function to fetch options from API
        const fetchOptions = async () => {
            try {
                const url = new URL(location);
                var version = url.searchParams.get("version");

                // Check if options are cached in localStorage and not expired
                const cachedOptions = localStorage.getItem("gh-releases");
                if (cachedOptions) {
                    const { data, timestamp } = JSON.parse(cachedOptions);
                    if (new Date().getTime() - timestamp < 600000) {
                        setOptions(data);
                        const versions = Object.keys(data);

                        // Prefer version from the query string, if present.
                        if (version !== "" && versions.includes(version)) {
                            setSelectedItem(version);
                            return;
                        }

                        // Auto-select the first option otherwise.
                        if (versions.length > 0) {
                            setSelectedItem(versions[0]);
                            return;
                        }
                    }
                }

                const response = await fetch(
                    "https://api.github.com/repos/openbao/openbao/releases",
                );
                if (!response.ok) {
                    throw new Error("Failed to fetch gh-releases");
                }
                const ghReleases = await response.json();
                const releases = GetReleases(ghReleases);
                const versions = Object.keys(releases);
                setOptions(releases);
                localStorage.setItem(
                    "gh-releases",
                    JSON.stringify({
                        data: releases,
                        timestamp: new Date().getTime(),
                    }),
                );

                // Prefer version from the query string, if present.
                if (version !== "" && versions.includes(version)) {
                    setSelectedItem(version);
                    return;
                }

                // Auto-select the first option.
                if (versions.length > 0) {
                    setSelectedItem(versions[0]);
                }
            } catch (error) {
                console.error(error);
            }
        };

        fetchOptions(); // Call the fetchOptions function when the component mounts
    }, []);

    return (
        <OptionsContext.Provider
            value={{ options, selectedItem, setSelectedItem }}
        >
            {children}
        </OptionsContext.Provider>
    );
};

// Custom hook to consume the context
const useOptions = () => useContext(OptionsContext);

const VersionSelect = () => {
    const { options, selectedItem, setSelectedItem } = useOptions();

    const handleSelectChange = (event) => {
        let version = event.target.value;
        setSelectedItem(version);

        const url = new URL(location);
        url.searchParams.set("version", version);
        history.replaceState({}, "", url);
    };

    return (
        <>
            <select
                value={selectedItem}
                onChange={handleSelectChange}
                className="button button--secondary margin-right--lg"
            >
                {Object.entries(options).map(([key, value]) => (
                    <option key={key} value={key} className={styles.options}>
                        {key}
                    </option>
                ))}
            </select>
        </>
    );
};

const Asset = ({ urls }) => {
    let asset: string;
    let gpgSig: string;
    let coCert: string;
    let coSig: string;
    let name: string = "Binary";

    for (let url of urls) {
        if (url.toLowerCase().includes(".deb")) {
            name = "Debian Package";
        } else if (url.toLowerCase().includes(".rpm")) {
            name = "RPM Package";
        } else if (url.toLowerCase().includes(".pkg") && url.toLowerCase().includes("linux")) {
            name = "Arch Package";
        }

        if (url.toLowerCase().includes(".gpgsig")) {
            gpgSig = url;
            continue;
        }
        if (url.toLowerCase().includes(".pem")) {
            coCert = url;
            continue;
        }
        if (url.toLowerCase().includes(".sig")) {
            coSig = url;
            continue;
        }
        asset = url;
    }

    if (asset === undefined) {
        return;
    }

    const { selectedItem } = useOptions();
    return (
        <div className="card download-card">
            <div className="pagination-nav__item">
                <div className="card__header">
                    <h5>
                        <a href={asset}>
                            {AssetArchitecture(asset).toUpperCase()} - {name}
                        </a>
                    </h5>
                </div>
                <div className="card__body">
                    <p className="text--center">
                        Version: {selectedItem}
                    </p>
                </div>
                <div className="card__footer">
                    <div class="button-group button-group--block">
                        <a class="button button--primary" href={asset}><span>Download</span></a>
                        {
                            gpgSig &&
                            <a class="button button--secondary" href={gpgSig}><span>GPG Signature</span></a>
                        }
                        {
                            coSig &&
                            <a class="button button--secondary" href={coSig}><span>Cosign Signature</span></a>
                        }
                        {
                            coCert &&
                            <a class="button button--secondary" href={coCert}><span>Cosign Certificate</span></a>
                        }
                    </div>
                </div>
            </div>
        </div>
    );
};

const DebRepo = ({ gpgKeyName }) => {
    const [gpgKey, setGPGKey] = useState("");
    useEffect(() => {
        try {
            fetch("/assets/" + gpgKeyName)
                .then(r => r.text())
                .then(data => setGPGKey(data.replace("\n\n", "\n.\n")))
        } catch (error) {
            console.error(error);
        }
    }, []);

    return (
        <div className="card__body">
            <h6>Set up the OpenBao repository</h6>
            Simply add this repository configuration to your DEB-sources.
            APT then verifies that the packages have been created and signed by the official pipeline and have not been tampered with.
            <CodeBlock
                language="shell"
                title="/etc/apt/sources.list.d/openbao.sources"
                showLineNumbers>
                {`Types: deb
URIs: https://pkgs.openbao.org/deb/
Suites: stable
Components: main
Signed-By:
` + gpgKey.replaceAll(/^(?!$)/gm, " ")}
            </CodeBlock>

            <h6>Install OpenBao</h6>
            <CodeBlock
                language="shell">
                {`sudo apt update && sudo apt install openbao`}
            </CodeBlock>
        </div>
    )
}

const RpmRepo = ({ gpgKeyName }) => {
    return (
        <div className="card__body">
            <h6>Set up the OpenBao repository</h6>
            Simply add this repository configuration to your YUM-repos.
            YUM then verifies that the packages have been created and signed by the official pipeline and have not been tampered with.
            <CodeBlock
                language="shell"
                title="/etc/yum.repos.de/openbao.repo"
                showLineNumbers>
                {`[openbao]
name=openbao
baseurl=https://pkgs.openbao.org/rpm/$basearch
repo_gpgcheck=0
gpgcheck=1
enabled=1
gpgkey=https://openbao.org/assets/` + gpgKeyName + `
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300`}
            </CodeBlock>

            <h6>Install OpenBao</h6>
            <CodeBlock
                language="shell">
                {`sudo yum install -y openbao`}
            </CodeBlock>
        </div>
    )
}

const PackageRepo = ({ type }) => {
    var gpgKeyName = "openbao-gpg-pub-20240618.asc";

    return (
        <div className="card download-card package-repo">
            <div className="card__header">
                <h5>Installation via official Package Repository</h5>
            </div>
            {type === 'deb' && <DebRepo gpgKeyName={gpgKeyName} />}
            {type === 'rpm' && <RpmRepo gpgKeyName={gpgKeyName} />}
        </div>
    )
}

const Docker = ({ version, name }) => {
    const { options } = useOptions();
    return (
        <Tabs>
            <TabItem value="quay" label="quay.io">
                <p>Alpine Image Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull quay.io/openbao/openbao:${version.slice(1)}`}
                </CodeBlock>
                <p>Red Hat Universal Base Image (UBI) Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull quay.io/openbao/openbao-ubi:${version.slice(1)}`}
                </CodeBlock>
                <p>HSM Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull quay.io/openbao/openbao-hsm-ubi:${version.slice(1)}`}
                </CodeBlock>
            </TabItem>
            <TabItem value="ghcr" label="ghcr.io">
                <p>Alpine Image Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull ghcr.io/openbao/openbao:${version.slice(1)}`}
                </CodeBlock>
                <p>Red Hat Universal Base Image (UBI) Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull ghcr.io/openbao/openbao-ubi:${version.slice(1)}`}
                </CodeBlock>
                <p>HSM Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull ghcr.io/openbao/openbao-hsm-ubi:${version.slice(1)}`}
                </CodeBlock>
            </TabItem>
            <TabItem value="docker" label="docker.io">
                <p>Alpine Image Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull docker.io/openbao/openbao:${version.slice(1)}`}
                </CodeBlock>
                <p>Red Hat Universal Base Image (UBI) Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull docker.io/openbao/openbao-ubi:${version.slice(1)}`}
                </CodeBlock>
                <p>HSM Distribution</p>
                <CodeBlock language="shell">
                    {`docker pull docker.io/openbao/openbao-hsm-ubi:${version.slice(1)}`}
                </CodeBlock>
            </TabItem>
        </Tabs>
    );
};

const LinuxPackage = ({ version, name }) => {
    const { options } = useOptions();
    return (
        <Tabs>
            <TabItem value="deb" label="DEB">
                <PackageRepo type={"deb"} />
                <nav className="pagination-nav">
                    {/* Check if version is not undefined before accessing releases */}
                    {version &&
                        Object(options)[version]["assets"][name] &&
                        Object(options)[version]["assets"][name]["deb"] &&
                        ArchPackageMapApply(
                            Object(options)[version]["assets"][name]["deb"],
                            (props, idx) => <Asset key={idx} urls={props} />,
                        )}
                </nav>
            </TabItem>
            <TabItem value="rpm" label="RPM">
                <PackageRepo type={"rpm"} />
                <nav className="pagination-nav">
                    {/* Check if version is not undefined before accessing releases */}
                    {version &&
                        Object(options)[version]["assets"][name] &&
                        Object(options)[version]["assets"][name]["rpm"] &&
                        ArchPackageMapApply(
                            Object(options)[version]["assets"][name]["rpm"],
                            (props, idx) => <Asset key={idx} urls={props} />,
                        )}
                </nav>
            </TabItem>
            <TabItem value="pkg" label="PKG">
                <nav className="pagination-nav">
                    {/* Check if version is not undefined before accessing releases */}
                    {version &&
                        Object(options)[version]["assets"][name] &&
                        Object(options)[version]["assets"][name]["pkg"] &&
                        ArchPackageMapApply(
                            Object(options)[version]["assets"][name]["pkg"],
                            (props, idx) => <Asset key={idx} urls={props} />,
                        )}
                </nav>
            </TabItem>
        </Tabs>
    );
};

const OS = ({ name }) => {
    const { options, selectedItem } = useOptions();
    var version = "";
    if (selectedItem === undefined && options) {
        version = Object.keys(options)[0];
    } else {
        version = selectedItem;
    }
    return (
        <div className="col col-12 margin-vert--md">
            <div className="card">
                <div className="card__header">
                    <h2>{OsPrettyPrint(name)}</h2>
                </div>
                <div className="card__body">
                    {name == "linux" ? (
                        <>
                            <h4>Docker</h4>
                            <Docker version={version} name={name} />
                            <h4>Package manager</h4>
                            <LinuxPackage version={version} name={name} />
                        </>
                    ) : (
                        <></>
                    )}
                    <h4>Binary download</h4>
                    <nav className="pagination-nav">
                        {/* Check if version is not undefined before accessing releases */}
                        {version &&
                            Object(options)[version]["assets"][name] &&
                            Object(options)[version]["assets"][name][
                                "binary"
                            ] &&
                            ArchPackageMapApply(
                                Object(options)[version]["assets"][name]["binary"],
                                (props, idx) => (
                                    <Asset key={idx} urls={props} />
                                )
                            )}
                    </nav>
                </div>
            </div>
        </div>
    );
};

const DownloadComponent = () => {
    const { options, selectedItem } = useOptions();
    var version = "";
    if (selectedItem === "" && options) {
        version = Object.keys(options)[0];
    } else {
        version = selectedItem;
    }

    var prerelease_notice = null;
    if (version && options[version]["assets"] !== undefined) {
        if (version.includes("alpha") || version.includes("beta")) {
            prerelease_notice = <div class="alert alert--danger" role="alert">
                <h3>Warning</h3>

                This is an <strong>unstable</strong>, prerelease build! Use at your own caution.
            </div>;
        }
    }

    return (
        <div className="container margin-vert--lg all-downloads">
            <div className="row">
                <div
                    className="col col--12 text--center margin-horiz--md"
                    style={{
                        display: "flex",
                        justifyContent: "space-between",
                    }}
                >
                    <h1 className="margin-bottom--none">Download OpenBao</h1>
                    <VersionSelect />
                </div>
            </div>
            <div className="row">
                <div
                    className="col col--12 text--center margin-horiz--md"
                    style={{
                        display: "flex",
                        justifyContent: "space-between",
                    }}
                >
                    <p className="text--left">
                        <br />
                        GPG Signatures are performed with our <a href="/assets/openbao-gpg-pub-20240618.asc">GPG key</a>.
                        SBOMs are available on our <a href={"https://github.com/openbao/openbao/releases/tag/" + version}>GitHub Release</a> page.
                        <br />
                        <br />
                        Check out our <a href="/docs/install/">installation guide</a> for more details!
                    </p>
                </div>
            </div>
            { prerelease_notice }
            {/* Check if version is not undefined before accessing releases */}
            {version &&
                options[version]["assets"] &&
                Object.entries(options[version]["assets"]).map(
                    ([key, value]) => (
                        <div className="row">
                            <OS name={key} />
                        </div>
                    ),
                )}
        </div>
    );
};

export default function Download(): JSX.Element {
    const { siteConfig } = useDocusaurusContext();

    return (
        <Layout title="Downloads" description="Download OpenBao">
            <OptionsProvider>
                <DownloadComponent />
            </OptionsProvider>
        </Layout>
    );
}
