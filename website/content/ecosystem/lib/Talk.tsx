import clsx from "clsx";
import styles from "./styles.module.css";

const favicon = "/img/favicon.svg"

import { getLogo } from './Member.tsx';

export function Talk({ title, memberName, children }) {
    const logo = memberName
        ? ( getLogo(memberName) ?? favicon)
        : favicon;

    return (
        <div className="col col--6 padding-bottom--lg">
            <div className="card card--full-height">
                <div className={clsx("card__header", styles.cardHeader)}>
                    <h2>{title}</h2>
                    <img className={styles.logo} src={logo} alt={`${memberName ?? "OpenBao"} logo`} />
                </div>
                <div className="card__body">
                    {children}
                </div>
            </div>
        </div>
    );
}

export function YouTubeTalk({ title, memberName, vid, lowres, children }) {
    const preview = lowres
        ? `https://i3.ytimg.com/vi/${vid}/mqdefault.jpg`
        : `https://img.youtube.com/vi/${vid}/maxresdefault.jpg`;

    return (
        <Talk title={title} memberName={memberName}>
            <a href={`https://youtube.com/watch?v=${vid}`}>
                <img src={preview} alt="Video Preview" style={{
                    width: "80%",
                    maxHeight: "200px",
                    margin: "0 auto",
                    display: "block",
                    paddingBottom: "25px",
                }} />
            </a>

            {children}

            <a href={`https://youtube.com/watch?v=${vid}`}>
                <i>Watch on YouTube.</i>
            </a>
        </Talk>
    );
}
