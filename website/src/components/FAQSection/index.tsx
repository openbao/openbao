"use client";
import React from "react";
import Accordion from "../Accordion";
import Heading from "@theme/Heading";

type AccordionItem = {
  title: string;
  description: JSX.Element;
};

const accordionData: AccordionItem[] = [
  {
    title: "What is OpenBao's mission statement?",
    description: (
      <>
        OpenBao exists to maintain and improve a software solution to manage,
        store, and distribute sensitive data including secrets, certificates,
        and keys. The OpenBao community will provide this software under an
        OSI-approved open-source license, led by a community run under open
        governance principles.
      </>
    ),
  },
  {
    title: "What is the status of the fork?",
    description: (
      <>
        The fork is now GA! Check out our{" "}
        <a href="https://github.com/openbao/openbao/releases">
          GitHub releases
        </a>
        {" "}or our{" "}
        <a href="/downloads">
          downloads page
        </a>.
      </>
    ),
  },
  {
    title: "Which version of Hashicorp Vault are you planning to fork from?",
    description: (
      <>
        OpenBao was forked prior to upstream's last commit
        (<a href="https://github.com/hashicorp/vault/commit/8993802145833ab01d49c6070d787a9eccb81546"><code>8993802</code></a>)
        prior to the BUSL. This corresponds to a few commits after 1.14.8,
        but prior to 1.14.9 being cut.

        From here forward, we'll be adhering to our{" "}
        <a href="/docs/policies/migration/#proposal">compatibility policy</a>{" "}
        to provide API-compatibility with upstream when possible.
      </>
    ),
  },
  {
    title: "How do I get involved?",
    description: (
      <>
        Check out our{" "}
        <a href="https://github.com/openbao/openbao/blob/main/CONTRIBUTING.md">
          contributing guide
        </a>
        {" "} for more information!
      </>
    ),
  },
  {
    title:
      "Will the existing MPL 2.0 licensed code be migrated to another license?",
    description: (
      <>
        There are no plans at this time to change the source code license. The
        MPL 2.0 includes a patent provision that grants users a license to any
        patents that are necessary to use the software.
      </>
    ),
  },
];
export default function FAQSection() {
  const [expanded, setExpanded] = React.useState<number>(0);
  return (
    <section className="padding-vert--md margin-vert--lg">
      <div className="container">
        <div className="row padding-bottom--md">
          <div className="col col--8 col--offset-2">
            <Heading
              as="h2"
              className="hero__title text--center padding-bottom--md"
            >
              Frequently Asked Questions
            </Heading>
            {accordionData.map((item, index) => (
              <Accordion
                key={index}
                item={item}
                isExpanded={index === expanded}
                onClick={() => setExpanded(index === expanded ? -1 : index)}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
