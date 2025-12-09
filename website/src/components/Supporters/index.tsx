import Heading from "@theme/Heading";

type SupportItem = {
    title: string;
    description: string;
};

const SupportList: SupportItem[] = [
    {
        title: "EdgeX Foundry",
        description: "Development; open-source community efforts",
    },
    {
        title: "IBM Edge Application Manager",
        description: "Open-source community efforts",
    },
    {
        title: "Open Horizon",
        description: "Development; open-source community efforts",
    },
    {
        title: "NS1",
        description: "Open-source community efforts",
    },
    {
        title: "IOTech Systems",
        description: "Open-source community efforts",
    },
    {
        title: "Viaccess-Orca",
        description: "Development; open-source community efforts",
    },
    {
        title: "WALLIX",
        description: "Development; open-source community efforts",
    },
    {
        title: "GitLab",
        description: "Development; open-source community efforts",
    },
    {
        title: "SAP",
        description: "Development; open-source community efforts",
    },
    {
        title: "NeoNephos",
        description: "Development; open-source community efforts",
    },
    {
        title: "Adfinis",
        description: "Development; open-source community efforts",
    },
    {
        title: "Liquid Reply",
        description: "Development; open-source community efforts",
    },
];

function Supporter({ title, description }: SupportItem) {
    return (
        <div className="row">
            <div
                className="col col--8 col--offset-2 padding-vert--md"
                style={{
                    "border-bottom": "solid 1px var(--ifm-table-border-color)",
                    gap: "1rem",
                    display: "flex",
                    "justify-content": "space-between",
                    "align-items": "center",
                }}
            >
                <span className="text--bold">{title}</span>
                <span className="text--light text--right">{description}</span>
            </div>
        </div>
    );
}

export default function Supporters(): JSX.Element {
    return (
        <section className="padding-vert--md margin-vert--lg">
            <div className="container">
                <div className="row padding-bottom--md">
                    <div className="col col--8 col--offset-2">
                        <Heading as="h2" className="hero__title text--center">
                            Supporters
                        </Heading>
                    </div>
                </div>
                {SupportList.map((props, idx) => (
                    <Supporter key={idx} {...props} />
                ))}
            </div>
        </section>
    );
}
