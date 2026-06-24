import clsx from "clsx";
import styles from "./styles.module.css";

const logos = require.context(
    "openbao-ecosystem-logos", true, /\.(svg|png)$/
);

import { useColorMode } from '@docusaurus/theme-common';


export function getLogo(title: string, logoName: string) {
    const key = logoName != null? logoName :title.trim().toLowerCase();

    const { colorMode } = useColorMode();

    const darkLogo = `./${key}/dark.svg`
    const lightLogo = `./${key}/light.svg`
    const darkLogoPng = `./${key}/dark.png`
    const lightLogoPng = `./${key}/light.png`

    if (colorMode == "dark" && logos.keys().includes(darkLogo)) {
        return logos(`${darkLogo}`).default ?? logos(`./${darkLogo}`);
    } else if (colorMode != "dark" && logos.keys().includes(lightLogo)) {
        return logos(`${lightLogo}`).default ?? logos(`./${lightLogo}`);
    } else if (colorMode == "dark" && logos.keys().includes(darkLogoPng)) {
        return logos(`${darkLogoPng}`).default ?? logos(`${darkLogoPng}`);
    } else if (colorMode != "dark" && logos.keys().includes(lightLogoPng)) {
        return logos(`${lightLogoPng}`).default ?? logos(`${lightLogoPng}`);
    } else if (logos.keys().includes(`./${key}.png`)) {
        return logos(`./${key}.png`).default ?? logos(`./${key}.png`);
    } else if (logos.keys().includes(`./${key}.svg`)) {
        return logos(`./${key}.svg`).default ?? logos(`./${key}.svg`);
    }
}

export default function Member({ title, logoName, children }) {
    const logo = getLogo(title, logoName);

    return (
        <div className="col col--6 padding-bottom--lg">
            <div className="card card--full-height">
                <div className={clsx("card__header", styles.cardHeader)}>
                    <h2>{title}</h2>
                    <img className={styles.logo} src={logo} alt={`${title} logo`} />
                </div>
                <div className="card__body">{children}</div>
            </div>
        </div>
    );
}
