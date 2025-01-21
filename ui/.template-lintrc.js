/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

'use strict';

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
    'no-builtin-form-components': 'off',
    'no-at-ember-render-modifiers': 'off',
  },
  ignore: ['lib/story-md', 'tests/**'],
};
