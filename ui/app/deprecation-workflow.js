/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import setupDeprecationWorkflow from 'ember-cli-deprecation-workflow';

export const deprecationWorkflowConfig = {
  // current output from deprecationWorkflow.flushDeprecations();
  // deprecations that will not be removed until 5.0.0 are filtered by deprecation-filter initializer rather than silencing below
  workflow: [
    { handler: 'log', matchId: 'ember-data:deprecate-array-like' },
    { handler: 'log', matchId: 'ember-data:deprecate-model-reopen' },
    { handler: 'log', matchId: 'ember-data:deprecate-model-reopenclass' },
    { handler: 'log', matchId: 'ember-data:deprecate-promise-proxies' },
    { handler: 'log', matchId: 'ember-data:deprecate-has-record-for-id' },
    { handler: 'log', matchId: 'ember-data:deprecate-promise-many-array-behaviors' },
    { handler: 'log', matchId: 'ember-data:no-a-with-array-like' },
    { handler: 'log', matchId: 'setting-on-hash' },
    { handler: 'log', matchId: 'ember-cli-page-object.multiple' },
    { handler: 'log', matchId: 'ember-cli-mirage-config-routes-only-export' },
    { handler: 'log', machtId: 'ember-engines.deprecation-camelized-engine-names' },
  ],
};

setupDeprecationWorkflow(deprecationWorkflowConfig);
