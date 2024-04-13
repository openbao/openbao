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
                // Check if options are cached in localStorage and not expired
                const cachedOptions = localStorage.getItem("options");
                if (cachedOptions) {
                    const { data, timestamp } = JSON.parse(cachedOptions);
                    if (new Date().getTime() - timestamp < 600000) {
                        setOptions(data);
                        const versions = Object.keys(data);
                        // Auto-select the first option
                        if (versions.length > 0) {
                            setSelectedItem(versions[0]);
                        }
                        return;
                    }
                }
                const response = await fetch(
                    "https://api.github.com/repos/openbao/openbao/releases",
                );
                if (!response.ok) {
                    throw new Error("Failed to fetch options");
                }
                const ghReleases = await response.json();
                const releases = GetReleases(ghReleases);
                const versions = Object.keys(releases);
                setOptions(releases);
                localStorage.setItem(
                    "options",
                    JSON.stringify({
                        data: releases,
                        timestamp: new Date().getTime(),
                    }),
                );

                // Auto-select the first option
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
        setSelectedItem(event.target.value);
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

const Asset = ({ url }) => {
    const { selectedItem } = useOptions();
    return (
        <div className="pagination-nav__item">
            <a className="pagination-nav__link" href={url}>
                <div className="pagination-nav__label">
                    {AssetArchitecture(url).toUpperCase()}
                </div>
                <div className="pagination-nav__sublabel">
                    Version: {selectedItem}
                </div>
            </a>
        </div>
    );
};

const Docker = ({ version, name }) => {
    const { options } = useOptions();
    return (
        <Tabs>
            {version &&
                Object(options)[version]["assets"][name] &&
                Object(options)[version]["assets"][name]["docker"] &&
                Object(options)[version]["assets"][name]["docker"].map(
                    (url) => (
                        <TabItem
                            value={AssetArchitecture(url)}
                            label={AssetArchitecture(url).toUpperCase()}
                        >
                            <CodeBlock language="shell">
                                {`curl -sL "${url}" -o openbao.tar;
unzip -p openbao.tar | docker load`}
                            </CodeBlock>
                        </TabItem>
                    ),
                )}
        </Tabs>
    );
};

const LinuxPackage = ({ version, name }) => {
    const { options } = useOptions();
    return (
        <Tabs>
            <TabItem value="deb" label="Deb">
                <nav className="pagination-nav">
                    {/* Check if version is not undefined before accessing releases */}
                    {version &&
                        Object(options)[version]["assets"][name] &&
                        Object(options)[version]["assets"][name]["deb"] &&
                        Object(options)[version]["assets"][name]["deb"].map(
                            (props, idx) => <Asset key={idx} url={props} />,
                        )}
                </nav>
            </TabItem>
            <TabItem value="rpm" label="RPM">
                <nav className="pagination-nav">
                    {/* Check if version is not undefined before accessing releases */}
                    {version &&
                        Object(options)[version]["assets"][name] &&
                        Object(options)[version]["assets"][name]["rpm"] &&
                        Object(options)[version]["assets"][name]["rpm"].map(
                            (props, idx) => <Asset key={idx} url={props} />,
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
                            Object(options)[version]["assets"][name][
                                "binary"
                            ].map((props, idx) => (
                                <Asset key={idx} url={props} />
                            ))}
                    </nav>
                </div>
            </div>
        </div>
    );
};

const DownloadComponent = () => {
    const { options, selectedItem } = useOptions();
    var version = "";
    if (selectedItem === undefined && options) {
        version = Object.keys(options)[0];
    } else {
        version = selectedItem;
    }
    return (
        <div className="container margin-vert--lg">
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
