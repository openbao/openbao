/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

'use strict';

const fs = require('fs');
let testOverrides = {};
try {
  const extractRuleNames = (filePath) => {
    const src = fs.readFileSync(filePath, 'utf-8');
    const names = [];
    // Match quoted rule names (single or double) used as keys in the rules object
    const ruleRegex = /['"]([a-z][a-z0-9-]*)['"]:\s/g;
    let match;
    while ((match = ruleRegex.exec(src)) !== null) {
      names.push(match[1]);
    }
    return names;
  };
  const recommendedRules = extractRuleNames('node_modules/ember-template-lint/lib/config/recommended.js');
  const stylisticRules = extractRuleNames('node_modules/ember-template-lint/lib/config/stylistic.js');
  const allRules = [...new Set([...recommendedRules, ...stylisticRules])];
  testOverrides = Object.fromEntries(allRules.map((name) => [name, false]));
  testOverrides.prettier = false;
} catch (error) {
  console.log(error); // eslint-disable-line
}

module.exports = {
  plugins: ['ember-template-lint-plugin-prettier'],
  extends: ['recommended', 'ember-template-lint-plugin-prettier:recommended'],
  rules: {
    'no-action': 'off',
    'no-implicit-this': {
      allow: ['supported-auth-backends'],
    },
    'require-input-label': 'off',
    'no-array-prototype-extensions': 'off',
    'no-unsupported-role-attributes': 'off',
  },
  ignore: ['lib/story-md', 'tests/**'],
  // ember language server vscode extension does not currently respect the ignore field
  // override all rules manually as workaround to align with cli
  overrides: [
    {
      files: ['**/*-test.js'],
      rules: testOverrides,
    },
  ],
};
