/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default Route.extend({
  store: service(),
  router: service(),

  beforeModel() {
    const itemType = this.modelFor('vault.cluster.access.identity');
    if (itemType !== 'entity') {
      return this.router.transitionTo('vault.cluster.access.identity');
    }
  },

  model() {
    const modelType = `identity/entity-merge`;
    return this.store.createRecord(modelType);
  },

  resetController(controller, isExiting) {
    this._super(...arguments);

    if (isExiting) {
      controller.cleanupModel?.();
    }
  },
});
