/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { registerDeprecationHandler } from '@ember/debug';

// https://guides.emberjs.com/release/configuring-ember/handling-deprecations/#toc_filtering-deprecations
export function initialize() {
  registerDeprecationHandler((message, options, next) => {
    // all deprecations are now handled
    next(message, options);
  });
}

export default { initialize };
