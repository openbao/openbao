import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import { includeMarkdown } from "@hashicorp/remark-plugins";
import path from "path";

const config: Config = {
  title: "OpenBao",
  tagline: "Manage, store and distribute sensitive data",
  favicon: "img/favicon.ico",

  // Set the production url of your site here
  url: "https://openbao.github.io",
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: "/openbao/",
  trailingSlash: true,

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "openbao", // Usually your GitHub org/user name.
  projectName: "openbao", // Usually your repo name.

  onBrokenLinks: "warn",
  onBrokenMarkdownLinks: "warn",
  // ignore broken anchors as most of them are false positives
  onBrokenAnchors: "ignore",

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },
  staticDirectories: ["public"],

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/openbao/openbao/tree/main/website/",
          remarkPlugins: [
            [
              includeMarkdown,
              {
                resolveMdx: true,
                resolveFrom: path.join(process.cwd(), "content", "partials"),
              },
            ],
          ],
          path: "content/docs",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],
  plugins: [
    [
      "@docusaurus/plugin-content-docs",
      {
        id: "api-docs",
        path: "content/api-docs",
        routeBasePath: "api-docs",
        sidebarPath: "./sidebarsApi.ts",
        editUrl: "https://github.com/openbao/openbao/tree/main/website/",
        remarkPlugins: [
          [
            includeMarkdown,
            {
              resolveMdx: true,
              resolveFrom: path.join(process.cwd(), "content", "partials"),
            },
          ],
        ],
      },
    ],
  ],

  themeConfig: {
    navbar: {
      title: "OpenBao",
      logo: {
        alt: "OpenBao Logo",
        src: "img/logo.svg",
      },
      items: [
        {
          to: "/docs/",
          label: "Docs",
          position: "left",
        },
        { to: "/api-docs/", label: "API", position: "left" },
        {
          href: "https://github.com/openbao/openbao",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            {
              label: "Intro",
              to: "/docs/",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "GitHub Discussions",
              href: "https://github.com/openbao/openbao/discussions",
            },
            {
              label: "Chat Server",
              href: "https://chat.lfx.linuxfoundation.org/",
            },
            {
              label: "Wiki",
              href: "https://wiki.lfedge.org/display/OH/OpenBao+%28Hashicorp+Vault+Fork+effort%29+FAQ",
            },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/openbao/openbao",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} The OpenBao Authors. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
