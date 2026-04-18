import React, { useState, useEffect, createContext, useContext, JSX, BaseSyntheticEvent } from "react";
import Layout from "@theme/Layout";
import Tabs from "@theme/Tabs";
import TabItem from "@theme/TabItem";
import CodeBlock from "@theme/CodeBlock";
import {
  GetReleases,
  AssetArchitecture,
  OsPrettyPrint,
  ArchPackageMapApply
} from "@site/src/components/Releases";
import CodeBlockWrap from "@site/src/components/CodeBlockWrap";
import Link from "@docusaurus/Link";
import Heading from '@theme/Heading'

// Create a context
const OptionsContext = createContext(null);

// Provider component
const OptionsProvider = ({ children }) => {
  const [options, setOptions] = useState({});
  const [selectedItem, setSelectedItem] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    // Function to fetch options from API
    const fetchOptions = async () => {
      try {
        const searchParams = new URLSearchParams(location.search);
        var version = searchParams.get("version");

        // Check if options are cached in localStorage and not expired
        const cachedOptions = localStorage.getItem("gh-releases");
        if (cachedOptions) {
          const { data, timestamp } = JSON.parse(cachedOptions);
          if (new Date().getTime() - timestamp < 600000) {
            setOptions(data);
            setLoading(false);
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
        setLoading(false);
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
        setLoading(false);
        setError(true);
      }
    };

    fetchOptions(); // Call the fetchOptions function when the component mounts
  }, []);

  return (
    <OptionsContext.Provider
      value={{ options, selectedItem, setSelectedItem, loading, error }}
    >
      {children}
    </OptionsContext.Provider>
  );
};

// Custom hook to consume the context
const useOptions = () => useContext(OptionsContext);

const VersionSelect = () => {
  const { options, selectedItem, setSelectedItem } = useOptions();

  const handleSelectChange = (event: BaseSyntheticEvent) => {
    let version = event.target.value;
    setSelectedItem(version);

    const url = new URL(location.href);
    url.searchParams.set("version", version);

    history.replaceState({}, "", url.href);
  };

  return (
    <>
      <select
        value={selectedItem}
        onChange={handleSelectChange}
        className="version-select"
      >
        {Object.entries(options).map(([key]) => (
          <option key={key} value={key}>
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
  let fileExtension: string = "";

  for (let url of urls) {
    const fileName = url.toLowerCase().split("/").pop().split("?")[0]

    const validExtensions = [
      ".tar.gz", ".deb", ".rpm", ".pkg.tar.zst", ".zip"
    ]

    if (fileName.endsWith(".gpgsig")) {
      gpgSig = url;
      continue;
    }
    if (fileName.endsWith(".pem")) {
      coCert = url;
      continue;
    }
    if (fileName.endsWith(".sigstore.json")) {
      coSig = url;
      continue;
    }

    for (const ext of validExtensions) {
      if (fileName.endsWith(ext)) {
        fileExtension = ext
      }
    }
    asset = url;
  }

  if (asset === undefined) {
    return;
  }

  const { selectedItem } = useOptions();
  const buttonText = fileExtension ? `Download ${fileExtension}` : "Download Binary";

  return (
    <div className="card download-card">
      <div className="card__header">
        <Heading as="h3" className="download-card__header-title">
          {AssetArchitecture(asset)}
        </Heading>
      </div>
      <div className="card__body">
        <p className="download-card__version">Version: {selectedItem}</p>
        <div className="download-card__content-wrapper">
          <div className="download-card__links">
            {gpgSig && (
              <Link href={gpgSig}>
                GPG Signature
              </Link>
            )}
            {coSig && (
              <Link href={coSig}>
                Cosign Signature
              </Link>
            )}
            {coCert && (
              <Link href={coCert}>
                Cosign Certificate
              </Link>
            )}
          </div>
          <div className="download-card__button-wrapper">
            <Link className="button button--primary" href={asset}>
              <span className="download-card__button-icon">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3"></path><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><path d="m7 10 5 5 5-5"></path></svg>
                {buttonText}
              </span>
            </Link>
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
        .then((r) => r.text())
        .then((data) => setGPGKey(data.replace("\n\n", "\n.\n")));
    } catch (error) {
      console.error(error);
    }
  }, []);

  return (
    <>
      <Heading as="h4">Installation via official Package Repository</Heading>
      Simply add this repository configuration to your DEB-sources. APT then
      verifies that the packages have been created and signed by the official
      pipeline and have not been tampered with.
      <CodeBlockWrap
        language="shell"
        title="/etc/apt/sources.list.d/openbao.sources"
        showLineNumbers
      >
        {`Types: deb
URIs: https://pkgs.openbao.org/deb/
Suites: stable
Components: main
Signed-By:
` + gpgKey.replaceAll(/^(?!$)/gm, " ")}
      </CodeBlockWrap>
      <Heading as="h4">Install OpenBao</Heading>
      <CodeBlock language="shell">
        {`sudo apt update && sudo apt install openbao`}
      </CodeBlock>
    </>
  );
};

const RpmRepo = ({ gpgKeyName }) => {
  return (
    <>
      <Heading as="h4">Installation via official Package Repository</Heading>
      Simply add this repository configuration to your YUM-repos. YUM then
      verifies that the packages have been created and signed by the official
      pipeline and have not been tampered with.
      <CodeBlock
        language="shell"
        title="/etc/yum.repos.de/openbao.repo"
        showLineNumbers
      >
        {`[openbao]
name=openbao
baseurl=https://pkgs.openbao.org/rpm/$basearch
repo_gpgcheck=0
gpgcheck=1
enabled=1
gpgkey=https://openbao.org/assets/` +
          gpgKeyName +
          `
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300`}
      </CodeBlock>
      <Heading as="h4">Install OpenBao</Heading>
      <CodeBlock language="shell">{`sudo yum install -y openbao`}</CodeBlock>
    </>
  );
};

const PackageRepo = ({ type }) => {
  var gpgKeyName = "openbao-gpg-pub-20240618.asc";

  return (
    <>
      {type === "deb" && <DebRepo gpgKeyName={gpgKeyName} />}
      {type === "rpm" && <RpmRepo gpgKeyName={gpgKeyName} />}
    </>
  );
};
const DockerList = ({ version, registry }) => {
  const dockerVersion = version.slice(1);

  // For example: 2.6.0, 2.5.0-beta20251125.
  // Consider replacing with a more complete semver parser once required.
  const [major, minor, _patch] = dockerVersion
    .match(/^(\d+)\.(\d+)\.(\d+)/).slice(1).map(v => parseInt(v));

  const dockerDistros = {
    "Alpine Image Distribution": "openbao/openbao",
    "Alpine Image Distribution with HSM Support": "openbao/openbao-hsm",
    "Red Hat Universal Base Image (UBI) Distribution": "openbao/openbao-ubi",
    "Red Hat Universal Base Image (UBI) Distribution with HSM support": "openbao/openbao-hsm-ubi",
    ...(major >= 2 && minor >= 6 ? {
      "Distroless Distribution": "openbao/openbao-distroless",
    } : {}),
  }
  return (
    <>
      {Object.entries(dockerDistros).map(([label, image]) => (
        <div key={label}>
          <p>{label}</p>
          <CodeBlock language="shell">
            {`docker pull ${registry}/${image}:${dockerVersion}`}
          </CodeBlock>
        </div>
      ))}
    </>
  )
}
const Docker = ({ version }) => {
  const registries = ["quay.io", "ghcr.io", "docker.io"];
  return (
    <Tabs>
      {registries.map((item) => (
        <TabItem key={item} value={item} label={item}>
          <DockerList version={version} registry={item} />
        </TabItem>
      ))}
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

  const tabConfig = {
    linux: [
      { type: "binary", label: "Binary", header: "Binary download" },
      { type: "docker", label: "Docker" },
      { type: "deb", label: "DEB", header: "DEB package download" },
      { type: "rpm", label: "RPM", header: "RPM package download" },
      { type: "pkg", label: "PKG", header: "Arch package download" },
    ],
    default: [
      { type: "binary", label: "Binary", header: "Binary download" },
    ],
  };

  const tabs = tabConfig[name] || tabConfig.default;

  const renderTabContent = (tab) => {
    const hasAssets = version && options[version]?.assets?.[name]?.[tab.type];

    if (tab.type === "docker") {
      return <Docker version={version} />;
    }

    return (
      <>
        <PackageRepo type={tab.type} />
        {tab.header && <Heading as="h4">{tab.header}</Heading>}
        {hasAssets && (
          <nav className="pagination-nav">
            {ArchPackageMapApply(
              options[version].assets[name][tab.type],
              (props, idx) => <Asset key={idx} urls={props} />,
            )}
          </nav>
        )}
      </>
    );
  };

  return (
    <div className="col col-12 margin-vert--md">
      <div className="card">
        <div className="card__header">
          <Heading as="h2">{OsPrettyPrint(name)}</Heading>
        </div>
        <div className="card__body">
          {tabs.length > 1 ? (
            <Tabs>
              {tabs.map((tab) => (
                <TabItem key={tab.type} value={tab.type} label={tab.label}>
                  {renderTabContent(tab)}
                </TabItem>
              ))}
            </Tabs>
          ) : (
            renderTabContent(tabs[0])
          )}
        </div>
      </div>
    </div>
  );
};

const DownloadComponent = ({gpgKeyName} : {gpgKeyName: string}) => {
  const { options, selectedItem, loading, error } = useOptions();
  let version: string;
  if (selectedItem === "" && options) {
    version = Object.keys(options)[0];
  } else {
    version = selectedItem;
  }

  var prerelease_notice = null;
  if (version && options[version]["assets"] !== undefined) {
    if (version.includes("alpha") || version.includes("beta")) {
      prerelease_notice = (
        <div className="alert alert--danger" role="alert">
          <Heading as="h3">Warning</Heading>
          This is an <strong>unstable</strong>, prerelease build! Use at your
          own caution.
        </div>
      );
    }
  }

  return (
    <div className="container margin-vert--lg all-downloads">
      <div className="row">
        <div
          className="col col--12 text--center margin-horiz--md downloads-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <Heading as='h1' className="margin-bottom--none">Download OpenBao</Heading>
          {!loading && !error && <VersionSelect />}
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
            GPG Signatures are performed with our{" "}
            <Link href={`pathname:///assets/${gpgKeyName}`}>GPG key</Link>. SBOMs
            are available on our{" "}
            <Link
              href={
                "https://github.com/openbao/openbao/releases/tag/" + version
              }
            >
              GitHub Release
            </Link>{" "}
            page.
            <br />
            <br />
            Check out our <Link href="/docs/install/">installation guide</Link> for
            more details!
          </p>
        </div>
      </div>
      {loading ? (
        <div className="row">
          <div className="col col--12 margin-horiz--md">
            <div className="alert alert--info" role="alert">
              <Heading as="h4">Loading...</Heading>
              Fetching release information from GitHub, please wait a moment.
            </div>
          </div>
        </div>
      ) : error ? (
        <div className="row">
          <div className="col col--12 margin-horiz--md">
            <div className="alert alert--danger" role="alert">
              <Heading as="h3">Failed to load releases</Heading>
              Unable to fetch releases from GitHub. Please try refreshing the
              page or visit the{" "}
              <Link href="https://github.com/openbao/openbao/releases">
                GitHub Releases page
              </Link>{" "}
              directly.
            </div>
          </div>
        </div>
      ) : (
        <>
          {prerelease_notice}
          {version &&
            options[version]["assets"] &&
            Object.entries(options[version]["assets"]).map(([key]) => (
              <div key={key} className="row">
                <OS name={key} />
              </div>
            ))}
        </>
      )}
    </div>
  );
};

export default function Download(): JSX.Element {
  return (
    <Layout title="Downloads" description="Download OpenBao">
      <OptionsProvider>
        <DownloadComponent gpgKeyName={"openbao-gpg-pub-20240618.asc"}/>
      </OptionsProvider>
    </Layout>
  );
}
