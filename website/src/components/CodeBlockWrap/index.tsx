import React from "react";
import CodeBlock from "@theme/CodeBlock";
import styles from "./styles.module.css";

type CodeBlockWrapProps = {
  children: React.ReactNode;
  language?: string;
  title?: string;
  showLineNumbers?: boolean;
};

const CodeBlockWrap = (props: CodeBlockWrapProps) => {
  const {children, language, title, showLineNumbers} = props

  const checkboxId = React.useId();

  return (
    <div className={styles.codeBlockWrap}>
      <input type="checkbox" id={checkboxId} className={styles.codeBlockCheck} />
      <div className={styles.codeBlock}>
        <CodeBlock language={language} title={title} showLineNumbers={showLineNumbers}>
          {children}
        </CodeBlock>
      </div>
      <label htmlFor={checkboxId} className={styles.codeBlockLabel} />
    </div>
  );
}

export default CodeBlockWrap
