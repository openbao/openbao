import Link from "@docusaurus/Link";
import {
  ArchPackageMap,
  ArchPackageMapApply,
  AssetArchitecture,
  GetReleases,
  OsPrettyPrint,
} from "@site/src/components/Releases";
import CodeBlock from "@theme/CodeBlock";
import Heading from "@theme/Heading";
import Layout from "@theme/Layout";
import TabItem from "@theme/TabItem";
import Tabs from "@theme/Tabs";
import {
  ChangeEvent,
  createContext,
  JSX,
  useContext,
  useEffect,
  useState,
} from "react";

import DebRepo from "./Downloads/Repoes/Debian";
import RpmRepo from "./Downloads/Repoes/Rpm";

type ReleaseAssets = Record<string, Record<string, ArchPackageMap>>;
interface DownloadRelease {
  assets: ReleaseAssets;
}

type ReleasesMap = Record<string, DownloadRelease>;

interface OptionsContextValue {
  options: ReleasesMap;
  selectedItem: string;
  setSelectedItem: (version: string) => void;
  loading: boolean;
  error: boolean;
}

interface CachedReleases {
  data: ReleasesMap;
  timestamp: number;
}

const CACHE_KEY = "gh-releases";
const CACHE_TTL_MS = 600_000; // 10 minutes
const GPG_KEY_NAME = "openbao-gpg-pub-20240618.asc";
const DOCKER_REGISTRIES = ["quay.io", "ghcr.io", "docker.io"] as const;

const OptionsContext = createContext<OptionsContextValue | null>(null);

const OptionsProvider = ({ children }: { children: React.ReactNode }) => {
  const [options, setOptions] = useState<ReleasesMap>({});
  const [selectedItem, setSelectedItem] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<boolean>(false);

  useEffect(() => {
    const fetchOptions = async () => {
      try {
        const searchParams = new URLSearchParams(location.search);
        const queryVersion = searchParams.get("version") ?? "";

        // Check cache
        const cached = localStorage.getItem(CACHE_KEY);
        if (cached) {
          const { data, timestamp }: CachedReleases = JSON.parse(cached);
          if (Date.now() - timestamp < CACHE_TTL_MS) {
            applyReleases(data, queryVersion);
            return;
          }
        }

        const response = await fetch(
          "https://api.github.com/repos/openbao/openbao/releases"
        );
        if (!response.ok) {
          throw new Error(`GitHub API error: ${response.status}`);
        }

        const ghReleases = await response.json();
        const releases: ReleasesMap = GetReleases(ghReleases);

        localStorage.setItem(
          CACHE_KEY,
          JSON.stringify({ data: releases, timestamp: Date.now() } satisfies CachedReleases)
        );

        applyReleases(releases, queryVersion);
      } catch (err) {
        console.error(err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };

    const applyReleases = (releases: ReleasesMap, queryVersion: string) => {
      setOptions(releases);
      const versions = Object.keys(releases);
      if (queryVersion && versions.includes(queryVersion)) {
        setSelectedItem(queryVersion);
      } else if (versions.length > 0) {
        setSelectedItem(versions[0]);
      }
    };

    fetchOptions();
  }, []);

  return (
    <OptionsContext.Provider
      value={{ options, selectedItem, setSelectedItem, loading, error }}
    >
      {children}
    </OptionsContext.Provider>
  );
};

const useOptions = (): OptionsContextValue => {
  const ctx = useContext(OptionsContext);
  if (!ctx) {
    throw new Error("useOptions must be used within OptionsProvider");
  }
  return ctx;
};

const VersionSelect = () => {
  const { options, selectedItem, setSelectedItem } = useOptions();

  const handleSelectChange = (event: ChangeEvent<HTMLSelectElement>) => {
    const version = event.target.value;
    setSelectedItem(version);

    const url = new URL(location.href);
    url.searchParams.set("version", version);
    history.replaceState({}, "", url.href);
  };

  return (
    <select
      value={selectedItem}
      onChange={handleSelectChange}
      className="version-select"
    >
      {Object.keys(options).map((key) => (
        <option key={key} value={key}>
          {key}
        </option>
      ))}
    </select>
  );
};

const VALID_EXTENSIONS = [".tar.gz", ".deb", ".rpm", ".pkg.tar.zst", ".zip"] as const;

interface AssetProps {
  urls: string[];
}

const Asset = ({ urls }: AssetProps) => {
  const { selectedItem } = useOptions();

  let asset: string | undefined;
  let gpgSig: string | undefined;
  let coCert: string | undefined;
  let coSig: string | undefined;
  let fileExtension = "";

  for (const url of urls) {
    const fileName = url.toLowerCase().split("/").pop()?.split("?")[0] ?? "";

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

    const matchedExt = VALID_EXTENSIONS.find((ext) => fileName.endsWith(ext));
    if (matchedExt) {
      fileExtension = matchedExt;
      asset = url;
    }
  }

  if (!asset) return null;

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
            {gpgSig && <Link href={gpgSig}>GPG Signature</Link>}
            {coSig && <Link href={coSig}>Cosign Signature</Link>}
            {coCert && <Link href={coCert}>Cosign Certificate</Link>}
          </div>
          <div className="download-card__button-wrapper">
            <Link className="button button--primary" href={asset}>
              <span className="download-card__button-icon">
                <DownloadIcon />
                {buttonText}
              </span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

const DownloadIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="18"
    height="18"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M12 15V3" />
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <path d="m7 10 5 5 5-5" />
  </svg>
);

type PackageRepoType = "deb" | "rpm" | string;

interface PackageRepoProps {
  type: PackageRepoType;
}

const PackageRepo = ({ type }: PackageRepoProps) => (
  <>
    {type === "deb" && <DebRepo gpgKeyName={GPG_KEY_NAME} />}
    {type === "rpm" && <RpmRepo gpgKeyName={GPG_KEY_NAME} />}
  </>
);

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

interface DockerListProps {
  version: string;
  registry: string;
}

const DockerList = ({ version, registry }: DockerListProps) => {
  // Strip leading "v": "v2.6.0" → "2.6.0"
  const dockerVersion = version.startsWith("v") ? version.slice(1) : version;

  const match = dockerVersion.match(/^(\d+)\.(\d+)\.(\d+)/);
  const [major, minor] = match
    ? [parseInt(match[1], 10), parseInt(match[2], 10)]
    : [0, 0];

  const dockerDistros: Record<string, string> = {
    "Alpine Image Distribution": "openbao/openbao",
    "Alpine Image Distribution with HSM Support": "openbao/openbao-hsm",
    "Red Hat Universal Base Image (UBI) Distribution": "openbao/openbao-ubi",
    "Red Hat Universal Base Image (UBI) Distribution with HSM support":
      "openbao/openbao-hsm-ubi",
    ...(major >= 2 && minor >= 6
      ? { "Distroless Distribution": "openbao/openbao-distroless" }
      : {}),
  };

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
  );
};

interface DockerProps {
  version: string;
}

const Docker = ({ version }: DockerProps) => (
  <Tabs>
    {DOCKER_REGISTRIES.map((registry) => (
      <TabItem key={registry} value={registry} label={registry}>
        <DockerList version={version} registry={registry} />
      </TabItem>
    ))}
  </Tabs>
);

type TabType = "binary" | "docker" | "deb" | "rpm" | "pkg";

interface TabConfig {
  type: TabType;
  label: string;
  header?: string;
}

const OS_TAB_CONFIG: Record<string, TabConfig[]> = {
  linux: [
    { type: "binary", label: "Binary", header: "Binary download" },
    { type: "docker", label: "Docker" },
    { type: "deb", label: "DEB", header: "DEB package download" },
    { type: "rpm", label: "RPM", header: "RPM package download" },
    { type: "pkg", label: "PKG", header: "Arch package download" },
  ],
};

const DEFAULT_TAB_CONFIG: TabConfig[] = [
  { type: "binary", label: "Binary", header: "Binary download" },
];

interface OSProps {
  name: string;
}

const OS = ({ name }: OSProps) => {
  const { options, selectedItem } = useOptions();
  const version = selectedItem || Object.keys(options)[0] || "";
  const tabs = OS_TAB_CONFIG[name] ?? DEFAULT_TAB_CONFIG;

  const renderTabContent = (tab: TabConfig) => {
    const hasAssets =
      version && options[version]?.assets?.[name]?.[tab.type];

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
              (props, arch) => <Asset key={arch} urls={props} />
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


const DownloadComponent = () => {
  const { options, selectedItem, loading, error } = useOptions();
  const version = selectedItem || Object.keys(options)[0] || "";
  const isPrerelease =
    version &&
    options[version]?.assets !== undefined &&
    (version.includes("alpha") || version.includes("beta"));

  return (
    <div className="container margin-vert--lg all-downloads">
      <div className="row">
        <div
          className="col col--12 text--center margin-horiz--md downloads-header"
          style={{ display: "flex", justifyContent: "space-between" }}
        >
          <Heading as="h1" className="margin-bottom--none">
            Download OpenBao
          </Heading>
          {!loading && !error && <VersionSelect />}
        </div>
      </div>

      <div className="row">
        <div
          className="col col--12 text--center margin-horiz--md"
          style={{ display: "flex", justifyContent: "space-between" }}
        >
          <p className="text--left">
            <br />
            GPG Signatures are performed with our{" "}
            <Link href={`pathname:///assets/${GPG_KEY_NAME}`}>GPG key</Link>.
            SBOMs are available on our{" "}
            <Link
              href={`https://github.com/openbao/openbao/releases/tag/${version}`}
            >
              GitHub Release
            </Link>{" "}
            page.
            <br />
            <br />
            Check out our{" "}
            <Link href="/docs/install/">installation guide</Link> for more
            details!
          </p>
        </div>
      </div>

      {loading ? (
        <div className="row">
          <div className="col col--12 margin-horiz--md">
            <div className="alert alert--info" role="alert">
              <Heading as="h4">Loading…</Heading>
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
          {isPrerelease && (
            <div className="alert alert--danger" role="alert">
              <Heading as="h3">Warning</Heading>
              This is an <strong>unstable</strong>, prerelease build! Use at
              your own caution.
            </div>
          )}
          {version &&
            options[version]?.assets &&
            Object.keys(options[version].assets).map((key) => (
              <div key={key} className="row">
                <OS name={key} />
              </div>
            ))}
        </>
      )}
    </div>
  );
};

const Download = (): JSX.Element => {
  return (
    <Layout title="Downloads" description="Download OpenBao">
      <OptionsProvider>
        <DownloadComponent />
      </OptionsProvider>
    </Layout>
  );
}


export default Download
