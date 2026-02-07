/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import UnsavedModelRoute from 'vault/mixins/unsaved-model-route';
import { inject as service } from '@ember/service';

export default Route.extend(UnsavedModelRoute, {
  store: service(),

  model() {
    const itemType = this.modelFor('vault.cluster.access.identity');
    const modelType = `identity/${itemType}`;
    return this.store.createRecord(modelType);
  },

  resetController(controller, isExiting) {
    this._super(...arguments);

    if (isExiting) {
      controller.cleanupModel?.();
    }
  },
});
