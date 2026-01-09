import clsx from "clsx";
import styles from "./styles.module.css";

const logos = require.context(
    "openbao-ecosystem-logos", false, /\.svg$/
);

export default function Member({ title, children }) {
    const key = title.trim().toLowerCase();
    const logo = logos(`./${key}.svg`).default ?? logos(`./${key}.svg`);
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
