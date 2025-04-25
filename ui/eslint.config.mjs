/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

'use strict';

import babelParser from '@babel/eslint-parser';
import ember from 'eslint-plugin-ember';
import emberRecommended from 'eslint-plugin-ember/configs/recommended';
import prettierRecommended from 'eslint-plugin-prettier/recommended';
import compat from 'eslint-plugin-compat';
import nodePlugin from 'eslint-plugin-n';
import js from '@eslint/js';
import globals from 'globals';
import qunitRecommended from 'eslint-plugin-qunit/configs/recommended';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  js.configs.recommended,
  ...emberRecommended,
  prettierRecommended,
  compat.configs['flat/recommended'],
  {
    ignores: [
      // unconventional js
      '/blueprints/*/files/',
      '/vendor/',
      '',
      // compiled output
      '/dist/',
      '/tmp/',
      '',
      // dependencies
      '/bower_components/',
      '/node_modules/',
      '/.yarn/',
      '',
      // misc
      '/coverage/',
      '!.*',
      '.*/',
      '.eslintcache',
      '',
      // ember-try
      '/.node_modules.ember-try/',
      '/bower.json.ember-try',
      '/npm-shrinkwrap.json.ember-try',
      '/package.json.ember-try',
      '/package-lock.json.ember-try',
      '/yarn.lock.ember-try',
      '/tests/helpers/vault-keys.js',
      '',
      // typescript declaration files
      '*.d.ts',
    ],
  },
  {
    languageOptions: {
      ecmaVersion: 2018,
      sourceType: 'module',
      parser: babelParser,
      globals: {
        ...globals.browser,
        // not sure why this isn't included in browser
        Intl: 'readonly',
      },
      parserOptions: {
        requireConfigFile: false,
        ecmaFeatures: {
          legacyDecorators: true,
        },
        babelOptions: {
          plugins: [['@babel/plugin-proposal-decorators', { version: 'legacy' }]],
        },
      },
    },
    plugins: { ember: ember },
    rules: {
      'no-console': 'error',
      'prefer-const': ['error', { destructuring: 'all' }],
      'ember/no-mixins': 'warn',
      'ember/no-new-mixins': 'off', // should be warn but then every line of the mixin is green
      // need to be fully glimmerized before these rules can be turned on
      'ember/no-classic-classes': 'off',
      'ember/no-classic-components': 'off',
      'ember/no-actions-hash': 'off',
      'ember/require-tagless-components': 'off',
      'ember/no-component-lifecycle-hooks': 'off',
      // I'm not really sure why, but this rule throws an exception.
      // Maybe because we are currently using an old version of ember?
      'ember/no-deprecated-router-transition-methods': 'off',
      // Might be good to enable this eventually, but currently
      // runloop functions are used quite a bit.
      'ember/no-runloop': 'off',
    },
  },
  // node files
  {
    ...nodePlugin.configs['flat/recommended-script'],
    files: [
      'eslint.config.js',
      '.prettierrc.js',
      '.template-lintrc.js',
      'ember-cli-build.js',
      'testem.js',
      'testem.enos.js',
      'blueprints/*/index.js',
      'config/**/*.js',
      'lib/*/index.js',
      'server/**/*.js',
      'scripts/**/*.js',
    ],
    languageOptions: {
      sourceType: 'script',
      globals: globals.node,
    },
    plugins: { n: nodePlugin },
    rules: {
      // this can be removed once the following is fixed
      // https://github.com/mysticatea/eslint-plugin-node/issues/77
      'node/no-unpublished-require': 'off',
    },
  },
  {
    files: ['scripts/codemods/**/*.js'],
    languageOptions: {
      sourceType: 'module',
    },
  },
  {
    // test files
    ...qunitRecommended,
    files: ['tests/**/*-test.{js,ts}'],
    rules: {
      'qunit/require-expect': 'off',
      'qunit/no-conditional-assertions': 'off',
      // We need to use run in some of our tests
      'ember/no-runloop': 'off',
    },
  },
  {
    files: ['**/*.ts'],
    extends: tseslint.configs.recommended,
  },
  {
    files: ['lib/**/*.{js,ts}'],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  {
    files: ['tests/**/*.{js,ts}'],
    languageOptions: {
      globals: {
        ...globals.embertest,
        server: 'writable',
        $: 'writable',
        authLogout: 'readonly',
        authLogin: 'readonly',
        pollCluster: 'readonly',
        mountSupportedSecretBackend: 'readonly',
      },
    },
  }
);
