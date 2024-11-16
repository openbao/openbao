import clsx from "clsx";
import Link from "@docusaurus/Link";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Layout from "@theme/Layout";
import HomepageFeatures from "@site/src/components/HomepageFeatures";
import Heading from "@theme/Heading";
import React from "react";
import LogoSvg from "@site/public/img/linux-foundation.svg";
import FAQSection from "@site/src/components/FAQSection";

import styles from "./index.module.css";
import Contributing from "@site/src/components/Contributing";
import Supporters from "../components/Supporters";

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx("hero hero--primary", styles.heroBanner)}>
      <div className="container">
        <div className="row">
          <div className="col col--8 col--offset-2">
            <LogoSvg
              style={{
                "max-width": "400px",
                width: "75%",
              }}
            />
            <Heading as="h1" className="hero__title">
              Manage, store, and distribute sensitive data with OpenBao
            </Heading>
            <p className="hero__subtitle">
              {siteConfig.title} is an open source, community-driven fork of Vault
              managed by the Linux Foundation.
            </p>
            <div className={styles.buttons}>
              <Link
                className="button button--secondary button--lg margin-bottom--md"
                to="/docs/what-is-openbao/"
              >
                What is OpenBao?
              </Link>
              &emsp;
              <Link
                className="button button--warning button--lg margin-bottom--md"
                to="/docs/install/"
              >
                Try it out!
              </Link>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

export default function Home(): JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout title={`${siteConfig.title}`} description={`${siteConfig.tagline}`}>
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <FAQSection />
        <Contributing />
        <Supporters />
      </main>
    </Layout>
  );
}
