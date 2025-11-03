import clsx from "clsx";
import styles from "./styles.module.css";

export default function Member({ title, children }) {
  let logo = require(
    `../../../node_modules/openbao-ecosystem-logos/${title.toLowerCase()}.svg`,
  ).default;
  return (
    <div className="col col--6 padding-bottom--lg">
      <div className="card card--full-height">
        <div className={clsx("card__header", styles.cardHeader)}>
          <h2>{title}</h2>
          <img className={styles.logo} src={logo} />
        </div>
        <div className="card__body">{children}</div>
      </div>
    </div>
  );
}
