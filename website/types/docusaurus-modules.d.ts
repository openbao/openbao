declare module "@theme/*" {
  import type { ComponentType } from "react";
  const component: ComponentType<any>;
  export default component;
}

declare module "@docusaurus/*" {
  export function useDocusaurusContext(): any;
}
