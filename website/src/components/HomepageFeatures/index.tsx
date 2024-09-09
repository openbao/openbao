import clsx from "clsx";
import Heading from "@theme/Heading";

type FeatureItem = {
  title: string;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: "Secure Secret Storage",
    description: (
      <>
        Arbitrary key/value secrets can be stored in OpenBao. OpenBao encrypts
        these secrets prior to writing them to persistent storage, so gaining
        access to the raw storage is not enough to access your secrets.
      </>
    ),
  },
  {
    title: "Dynamic Secrets",
    description: (
      <>
        OpenBao can generate secrets on-demand for some systems, such as
        Kubernetes or SQL databases. After creating these dynamic secrets,
        OpenBao will also automatically revoke them after the lease is up.
      </>
    ),
  },
  {
    title: "Data Encryption",
    description: (
      <>
        OpenBao provides encryption as a service with centralized key management
        to simplify encrypting data in transit and stored across clouds and
        datacenters.
      </>
    ),
  },
  {
    title: "Identity based access",
    description: (
      <>
        Organizations need a way to manage identity sprawl with the use of
        different clouds, services, and systems. OpenBao solves this challenge
        by using a unified ACL system to broker access to systems and secrets
        and merges identities across providers.
      </>
    ),
  },
  {
    title: "Leasing and Renewal",
    description: (
      <>
        All secrets in OpenBao have a lease associated with them. At the end of
        the lease, OpenBao will automatically revoke that secret. Clients are
        able to renew leases via built-in renew APIs.
      </>
    ),
  },
  {
    title: "Revocation",
    description: (
      <>
        OpenBao has built-in support for secret revocation. OpenBao can revoke
        not only single secrets, but a tree of secrets, for example all secrets
        read by a specific user, or all secrets of a particular type.
      </>
    ),
  },
];

function Feature({ title, description }: FeatureItem) {
  return (
    <div className={clsx("col col--4 padding-bottom--lg")}>
      <div className="card card--full-height">
        <div className="card__header">
          <h3>{title}</h3>
        </div>
        <div className="card__body">
          <p>{description}</p>
        </div>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className="padding-vert--md margin-vert--lg">
      <div className="container">
        <Heading as="h2" className="hero__title text--center">
          Use cases
        </Heading>
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
