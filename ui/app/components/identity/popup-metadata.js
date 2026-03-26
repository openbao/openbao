/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Base from './_popup-base';
import { computed } from '@ember/object';

export default Base.extend({
  model: computed('params', function () {
    return this.params[0];
  }),

  key: computed('params', function () {
    return this.params[1];
  }),

  messageArgs(model, key) {
    return [model, key];
  },

  successMessage(model, key) {
    return `Successfully removed '${key}' from metadata`;
  },
  errorMessage(e, model, key) {
    const error = e.errors ? e.errors.join(' ') : e.message;
    return `There was a problem removing '${key}' from the metadata - ${error}`;
  },

  transaction(model, key) {
    const metadata = model.metadata;
    delete metadata[key];
    model.set('metadata', { ...metadata });
    return model.save();
  },
});
