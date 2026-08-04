/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

// Catch aborted transition errors. These are part of normal control flow, but
// return an error which needs to be handled.
export default function transitionToSafe(router, ...args) {
  return router.transitionTo(...args).catch((error) => {
    if (error?.name !== 'TransitionAborted') {
      throw error;
    }
  });
}
