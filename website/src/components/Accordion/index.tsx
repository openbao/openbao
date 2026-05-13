import { KeyboardEvent, ReactNode } from "react";
import styles from "./styles.module.css";
import Heading from "@theme/Heading";

export type AccordionItem = {
  title: string;
  description: ReactNode;
};

export type AccordionProps = {
  item: AccordionItem;
  isExpanded: boolean;
  onClick: () => void;
};

const Accordion = (props: AccordionProps) => {
  const {
    onClick,
    isExpanded,
    item,
  } = props


  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Enter") {
      onClick();
    }
  }

  return (
    <>
      <div
        className={styles.accordion__item}
        onClick={onClick}
        tabIndex={0}
        role="button"
        onKeyDown={handleKeyDown}
      >
        <div
          className={styles.accordion__item__title}
          aria-expanded={isExpanded}
          aria-label={(isExpanded ? "hide " : "show ") + item.description}
        >
          <Heading as="h3" className="margin-vert--none">{item.title}</Heading>
          <Heading as="h3" className="margin-vert--none">{isExpanded ? "-" : "+"}</Heading>
        </div>
        {isExpanded ? (
          <div className={styles.accordion__item__description}>
            <p className="margin-bottom--none">{item.description}</p>
          </div>
        ) : null}
      </div>
    </>
  );
}

export default Accordion
