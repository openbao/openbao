import Heading from "@theme/Heading";
import Link from "@docusaurus/Link";

export default function Contributing(): JSX.Element {
    return (
        <section className="padding-vert--md margin-vert--lg">
            <div className="container">
                <div className="row">
                    <div className="col col--8 col--offset-2">
                        <Heading as="h2" className="hero__title text--center">
                            Contributing
                        </Heading>
                        <div className="hero__subtitle text--center">
                            The best way to support the OpenBao project is to
                            contribute. The contribution guide explains
                            recommended practices, how to submit issues, how to
                            get involved in the discussion and much more.
                        </div>
                        <div className="padding--md text--center">
                            <Link
                                className="button button--warning button--lg"
                                to="https://github.com/openbao/openbao/blob/main/CONTRIBUTING.md"
                            >
                                Get involved!
                            </Link>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}
