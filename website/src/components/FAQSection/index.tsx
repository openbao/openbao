"use client";
import Heading from "@theme/Heading";
import React from "react";
import Accordion from "../Accordion";
import accordionData from "./accordiondata";

const FAQSection = () => {
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
            {accordionData?.map((item, index) => (
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

export default FAQSection
