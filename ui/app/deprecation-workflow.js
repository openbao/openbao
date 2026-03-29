/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import setupDeprecationWorkflow from 'ember-cli-deprecation-workflow';

export const deprecationWorkflowConfig = {
  // current output from deprecationWorkflow.flushDeprecations();
  // deprecations that will not be removed until 5.0.0 are filtered by deprecation-filter initializer rather than silencing below
  workflow: [],
};

setupDeprecationWorkflow(deprecationWorkflowConfig);
