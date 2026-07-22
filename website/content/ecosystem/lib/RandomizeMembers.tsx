import Randomize from "./Randomize.tsx";
import clsx from "clsx";
import styles from "./styles.module.css";
import { useColorMode } from '@docusaurus/theme-common';

const logos = require.context(
    "openbao-ecosystem-logos", true, /\.(svg|png)$/
);


function transformLogos() {
  console.log(logos);

  const { colorMode } = useColorMode();

  var vendors = {};
  for (const logo_idx in logos.keys()) {
    const logo = logos.keys()[logo_idx];

    const dark_logo = logo.includes("/dark.png") || logo.includes("/dark.svg");
    const light_logo = logo.includes("/light.png") || logo.includes("/light.svg");
    const dark_mode = colorMode == "dark";

    const vendor = logo.substring(2).split(".")[0].split("/")[0];
    console.log("logo", logo, "vendor", vendor);

    const use_dark = dark_logo && dark_mode;
    const use_light = light_logo && !dark_mode;
    const new_vendor = !(vendor in vendors);

    if (use_dark || use_light || new_vendor) {
      vendors[vendor] = logo;
    }
  }

  var rendered = [];

  for (const vendor_name in vendors) {
    const logo = vendors[vendor_name];
    const ref = logos(logo).default ?? logos(logo);

    rendered.push(
      <div className="col col--2 padding-bottom--lg">
        <div className="card card--full-height">
          <div className={clsx("card__header", styles.centered )}>
            <img id={vendor_name} className={styles.logoOnly} src={ref} alt={`${vendor_name} logo`} />
          </div>
        </div>
      </div>
    );
  }

  return rendered;
}

export default function RandomizeMembers() {
  const rendered = transformLogos();
  return (
    <div className="row">
      <Randomize>
        { ...rendered }
      </Randomize>
    </div>
  );
}
