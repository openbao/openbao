import Randomize from "./Randomize";
import { getLogo } from "./Member";
import clsx from "clsx";
import styles from "./styles.module.css";

const logos = require.context("openbao-ecosystem-logos", true, /\.(svg|png)$/);

export default function RandomizeMembers() {
  // Collect the unique set of logos, deduplicating dark/light mode ones.
  const names = [
    ...new Set(
      logos.keys().map((path) => path.substring(2).split(".")[0].split("/")[0]),
    ).values(),
  ];

  return (
    <div className="row">
      <Randomize>
        {names.map((name) => {
          const logo = getLogo(name, name);
          return (
            <div className="col col--2 padding-bottom--lg">
              <div className="card card--full-height">
                <div className={clsx("card__header", styles.centered)}>
                  <img
                    id={name}
                    className={styles.logoOnly}
                    src={logo}
                    alt={`${name} logo`}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </Randomize>
    </div>
  );
}
