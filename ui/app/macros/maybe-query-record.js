/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { computed } from '@ember/object';
import { resolve } from 'rsvp';

export function maybeQueryRecord(modelName, options = {}, ...keys) {
  return computed(...keys, 'store', {
    get() {
      const query = typeof options === 'function' ? options(this) : options;
      return query ? this.store.queryRecord(modelName, query) : resolve({});
    },
  });
}
