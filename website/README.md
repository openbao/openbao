# OpenBao Website

This subdirectory contains the content for the [OpenBao
Website](https://openbao.org).  It is built using
[Docusaurus](https://docusaurus.io), a modern static site generator.

## Table of Contents

- [Contributions](#contributions-welcome)
- [Running the Site Locally](#running-the-site-locally)
- [Editing Markdown Content](#editing-markdown-content)
- [Editing Navigation Sidebars](#editing-navigation-sidebars)
- [Deployment](#deployment)

## Contributions Welcome!

If you find a typo or you feel like you can improve the HTML, CSS, or
JavaScript, we welcome contributions. Feel free to open issues or pull requests
like any normal GitHub project, and we'll merge it in 🚀

## Running the Site Locally

The website can be run locally through node.js.  If your local development
environment has a supported version (v18.0.0+) of [node
installed](https://nodejs.org/en/) you can run:

- `make`

...and then visit `http://localhost:3000/openbao`.

## Editing Markdown Content

Documentation content is written in
[Markdown](https://www.markdownguide.org/cheat-sheet/) and you'll find all files
listed under the `/content` directory.

To create a new page with Markdown, create a file ending in `.mdx` in a
`content/<subdirectory>`. The path in the content directory will be the URL
route. For example, `content/docs/hello.mdx` will be served from the
`/docs/hello` URL.

This file can be standard Markdown and also supports [YAML
frontmatter](https://middlemanapp.com/basics/frontmatter/). YAML frontmatter is
optional, there are defaults for all keys.

```yaml
---
title: 'My Title'
description: "A thorough, yet succinct description of the page's contents"
---
```

The significant keys in the YAML frontmatter are:

- `title` `(string)` - This is the title of the page that will be set in the
  HTML title.
- `description` `(string)` - This is a description of the page that will be set
  in the HTML description.

### Markdown Enhancements

There are several custom markdown plugins that are available by default that
enhance [standard markdown](https://commonmark.org/) to fit our use cases. This
set of plugins introduces a couple instances of custom syntax, and a couple
specific pitfalls that are not present by default with markdown, detailed below:

- If you see `@include '/some/path.mdx'`, this is a [markdown
  include](https://github.com/hashicorp/remark-plugins/tree/master/plugins/include-markdown#include-markdown-plugin).
  It's worth noting as well that all includes resolve from
  `website/content/partials` by default, and that changes to partials will not
  live-reload the website.
- If you see `# Headline {#slug}`, this is an example of a [heading
  ID](https://docusaurus.io/docs/markdown-features/toc#heading-ids). It adds an
  extra permalink to a headline for compatibility and is removed from the
  output.
- Due to automatically generated headline IDs, any text changes to _headlines_
  can and will break existing permalinks. Be very cautious when changing either
  of these.

### Custom Components

A number of custom [mdx components](https://mdxjs.com/) are available for use
within any `.mdx` file. Please consult the [Docusaurus
documentation](https://docusaurus.io/docs/markdown-features) for more
information about them.

### Syntax Highlighting

When using fenced code blocks, the recommendation is to tag the code block with
a language so that it can be syntax highlighted. For example:

````markdown
```
// BAD: Code block with no language tag
```

```javascript
// GOOD: Code block with a language tag
```
````

Check out the [supported languages
list](https://prismjs.com/#supported-languages) for the syntax highlighter we
use if you want to double check the language name.

It is also worth noting specifically that if you are using a code block that is
an example of a terminal command, the correct language tag is `shell-session`.
For example:

🚫**BAD**: Using `shell`, `sh`, `bash`, or `plaintext` to represent a terminal
command

````markdown
```shell
$ terraform apply
```
````

✅**GOOD**: Using `shell-session` to represent a terminal command

````markdown
```shell-session
$ terraform apply
```
````

## Editing Navigation Sidebars

The structure of the sidebars are controlled by the `sidebar.ts` and
`sidebarApi.ts` files. For example, [sidebar.ts](sidebar.ts) controls the
**docs** sidebar. Please consult the [Docusaurus
documentation](https://docusaurus.io/docs/sidebar/items) on how to edit the
sidebars.

## Deployment

This website is hosted on GitHub Pages and configured to automatically deploy
anytime you push code to the `gh-pages` branch. To perform a manual deployment
run the following command:

```console
$ GIT_USER=<Your GitHub username> yarn deploy
```
