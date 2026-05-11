/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Application from 'vault/app';
import config from 'vault/config/environment';
import * as QUnit from 'qunit';
import { setApplication } from '@ember/test-helpers';
import { setup } from 'qunit-dom';
import { start } from 'ember-qunit';
import { registerDeprecationHandler } from '@ember/debug';
import { detectWorkflow } from 'ember-cli-deprecation-workflow';
import { deprecationWorkflowConfig } from 'vault/deprecation-workflow';
import './helpers/flash-message';
import preloadAssets from 'ember-asset-loader/test-support/preload-assets';
import manifest from 'vault/config/asset-manifest';

// Forward deprecations that are explicitly marked as `handler: 'log'` in
// app/deprecation-workflow.js to QUnit as test failures, so they appear in
// stdout rather than only in the browser console.
registerDeprecationHandler((message, options, next) => {
  const workflow = detectWorkflow(deprecationWorkflowConfig, message, options);
  if (workflow?.handler === 'log') {
    const currentTest = QUnit.config.current;
    if (currentTest) {
      currentTest.assert.pushResult({
        result: false,
        actual: options?.id ?? message,
        expected: 'no deprecation',
        message: `Unexpected deprecation: ${message}`,
      });
    }
  }
  next(message, options);
});

preloadAssets(manifest).then(() => {
  setApplication(Application.create(config.APP));
  // TODO CBS: Check what this is, upgrade added it
  setup(QUnit.assert);
  start({
    setupTestIsolationValidation: true,
  });
});

// Stub window.confirm for tests to prevent Testem browser disconnect errors
if (window.confirm.isSinonProxy !== true) {
  window._originalConfirm = window.confirm;
  window.confirm = () => true; // Default to accepting all confirms in tests
}
