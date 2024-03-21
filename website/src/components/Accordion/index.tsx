import styles from "./styles.module.css";

type AccordionItem = {
  title: string;
  description: string;
};
type AccordionProps = {
  item: AccordionItem;
  isExpanded: boolean;
  onClick: () => void;
};
export default function Accordion({
  item,
  isExpanded,
  onClick,
}: AccordionProps) {
  return (
    <>
      <div
        className={styles.accordion__item}
        onClick={onClick}
        tabIndex={0}
        role="button"
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            onClick();
          }
        }}
      >
        <div
          className={styles.accordion__item__title}
          aria-expanded={isExpanded}
          aria-label={(isExpanded ? "hide " : "show ") + item.description}
        >
          <h3 className="margin-vert--none">{item.title}</h3>
          <h3 className="margin-vert--none">{isExpanded ? "-" : "+"}</h3>
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
