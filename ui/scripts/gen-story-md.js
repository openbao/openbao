#!/usr/bin/env node
/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/* eslint-disable */
// run this script via pnpm in the ui directory:
// pnpm gen-story-md some-component
//
// or if the story is for a component in an in-repo-addon or an engine:
// pnpm gen-story-md some-component name-of-engine

const fs = require('fs');
const path = require('path');
const jsdoc2md = require('jsdoc-to-markdown');
var args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: pnpm gen-story-md <component-name> [addon-or-engine]');
  process.exit(1);
}
const name = args[0];
const addonOrEngine = args[1];
const inputFile = addonOrEngine
  ? `lib/${addonOrEngine}/addon/components/${name}.js`
  : `app/components/${name}.js`;
const outputFile = addonOrEngine ? `lib/${addonOrEngine}/stories/${name}.md` : `stories/${name}.md`;

if (!fs.existsSync(inputFile)) {
  console.error(`Input file not found: ${inputFile}`);
  process.exit(1);
}

const templatePath = path.resolve('./lib/story-md.hbs');
if (!fs.existsSync(templatePath)) {
  console.error(`Template not found: ${templatePath}`);
  process.exit(1);
}

const component = name
  .split('-')
  .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
  .join('');
const options = {
  files: inputFile,
  template: fs.readFileSync(templatePath, 'utf8'),
  'example-lang': 'js',
};
let md;
try {
  md = jsdoc2md.renderSync(options);
} catch (error) {
  console.error(`jsdoc2md failed: ${error.message}`);
  process.exit(1);
}

const pageBreakIndex = md.lastIndexOf('---'); //this is our last page break

const seeLinks = `**See**
- [Uses of ${component}](https://github.com/openbao/openbao/search?l=Handlebars&q=${component}+OR+${name})
- [${component} Source Code](https://github.com/openbao/openbao/blob/main/ui/${inputFile})
`;
const generatedWarning = `<!--THIS FILE IS AUTO GENERATED. This file is generated from JSDoc comments in ${inputFile}. To make changes, first edit that file and run "pnpm gen-story-md ${name}" to re-generate the content.-->
`;
md = generatedWarning + md.slice(0, pageBreakIndex) + seeLinks + md.slice(pageBreakIndex);

fs.writeFileSync(outputFile, md);
