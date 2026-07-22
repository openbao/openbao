import clsx from "clsx";
import styles from "./styles.module.css";

const favicon = "/img/favicon.svg"

import { getLogo } from './Member.tsx';

export function News({ title, memberName, children }) {
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

export function NewsBlurb({ title, memberName, link, children }) {
    const domain = URL.parse(link).hostname;

    return (
        <News title={title} memberName={memberName}>
            { children }


            <a href={link} target="_blank">
                <i>Continue reading on {domain}.</i>
            </a>
        </News>
    );
}

export function YouTubeTalk({ title, memberName, vid, lowres, children }) {
    const preview = lowres
        ? `https://i3.ytimg.com/vi/${vid}/mqdefault.jpg`
        : `https://img.youtube.com/vi/${vid}/maxresdefault.jpg`;

    return (
        <News title={title} memberName={memberName}>
            <a href={`https://youtube.com/watch?v=${vid}`}>
                <img src={preview} alt="Video Preview" style={{
                    maxHeight: "min(200px, 30vh)",
                    maxWidth: "min(400px, 70vw)",
                    margin: "0 auto",
                    display: "block",
                    paddingBottom: "25px",
                }} />
            </a>

            {children}

            <a href={`https://youtube.com/watch?v=${vid}`} target="_blank">
                <i>Watch on YouTube.</i>
            </a>
        </News>
    );
}
