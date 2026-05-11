/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default Route.extend({
  store: service(),

  model(params) {
    const itemType = this.modelFor('vault.cluster.access.identity');
    const modelType = `identity/${itemType}-alias`;
    return this.store.findRecord(modelType, params.item_alias_id);
  },

  resetController(controller, isExiting) {
    this._super(...arguments);

    if (isExiting) {
      controller.cleanupModel?.();
    }
  },
});
