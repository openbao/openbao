import React, { type ReactNode } from "react";
import DocsVersionDropdownNavbarItem from "@theme-original/NavbarItem/DocsVersionDropdownNavbarItem";
import type DocsVersionDropdownNavbarItemType from "@theme/NavbarItem/DocsVersionDropdownNavbarItem";
import type { WrapperProps } from "@docusaurus/types";
import { useActiveDocContext } from "@docusaurus/plugin-content-docs/client";

type Props = WrapperProps<typeof DocsVersionDropdownNavbarItemType>;

export default function DocsVersionDropdownNavbarItemWrapper(
  props: Props,
): ReactNode {
  const activeDocContext = useActiveDocContext(props.docsPluginId);
  if (!activeDocContext.activeDoc) {
    return null;
  }
  return (
    <>
      <DocsVersionDropdownNavbarItem {...props} />
    </>
  );
}
