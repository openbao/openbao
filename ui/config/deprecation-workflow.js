/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

self.deprecationWorkflow = self.deprecationWorkflow || {};
//self.deprecationWorkflow.config = {
//throwOnUnhandled: true
//}
self.deprecationWorkflow.config = {
  // current output from deprecationWorkflow.flushDeprecations();
  // deprecations that will not be removed until 5.0.0 are filtered by deprecation-filter initializer rather than silencing below
  workflow: [],
};
