export type AccordionItem = {
  title: string;
  description: string;
};

export type AccordionProps = {
  item: AccordionItem;
  isExpanded: boolean;
  onClick: () => void;
};
