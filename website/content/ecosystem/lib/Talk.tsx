import clsx from "clsx";
import styles from "./styles.module.css";

const favicon = "/img/favicon.svg"

import { getLogo } from './Member.tsx';

function getOptionalLogo(member) {
    if (member === undefined) {
        return favicon;
    }

    const logo = getLogo(member);
    if (logo === undefined) {
        return favicon;
    }

    return logo;
}

export function Talk({ title, memberName, children }) {
    const logo = getOptionalLogo(memberName);

    return (
        <div className="col col--6 padding-bottom--lg">
            <div className="card card--full-height">
                <div className={clsx("card__header", styles.cardHeader)}>
                    <h2>{title}</h2>
                    <img className={styles.logo} src={logo} alt={`${memberName} logo`} />
                </div>
                <div className="card__body">
                    {children}
                </div>
            </div>
        </div>
    );
}

export default function YouTubeTalk({ title, memberName, vid, lowres, children }) {
    let preview = `https://img.youtube.com/vi/${ vid }/maxresdefault.jpg`;
    if (lowres) {
        preview = `https://i3.ytimg.com/vi/${ vid }/mqdefault.jpg`;
    }

    return (
        <Talk title={ title } memberName={ memberName }>
            <a href={`https://youtube.com/watch?v=${ vid }`}>
                <img src={ preview } alt="Video Preview" style={{
                    width: "80%",
                    maxHeight: "200px",
                    margin: "0 auto",
                    display: "block",
                    paddingBottom: "25px",
                }} />
            </a>

            { children }

            <a href={`https://youtube.com/watch?v=${ vid }`}>
                <i>Watch on YouTube.</i>
            </a>
        </Talk>
    );
}
