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
    title: "Is the forked code available?",
    description: (
      <>
        It is being worked on at{" "}
        <a href="https://github.com/openbao/openbao">
          github.com/openbao/openbao
        </a>{" "}
        in the main branch. Upcoming releases have their own branches.
      </>
    ),
  },
  {
    title: "Which version of Hashicorp Vault are you planning to fork?",
    description: (
      <>
        The{" "}
        <a href="https://github.com/hashicorp/vault/tree/release/1.14.x">
          1.14.x release
        </a>{" "}
        is the most recent that is under an MPL 2.0 license, and will be
        receiving official updates until December 31, 2023. Our fork will be
        based on the newest point release in that branch.
      </>
    ),
  },
  {
    title: "How do I get involved?",
    description: (
      <>
        Subscribe to the{" "}
        <a href="https://lists.lfedge.org/g/openbao">
          OpenBao meetings and mailing list
        </a>
        . The meetings are scheduled for Thursday mornings at 9:00am US Eastern,
        beginning November 9th 2023. Community decisions and discussions happen
        in GitHub Discussions, and daily chatter takes place in the "openbao-*"
        chat rooms on the LFX Matrix chat server (login with your LF ID).
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
                onClick={() => setExpanded(index)}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
