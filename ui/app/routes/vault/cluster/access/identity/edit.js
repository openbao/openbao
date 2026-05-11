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
    const modelType = `identity/${itemType}`;
    return this.store.findRecord(modelType, params.item_id);
  },

  resetController(controller, isExiting) {
    this._super(...arguments);

    if (isExiting) {
      controller.cleanupModel?.();
    }
  },

  actions: {
    willTransition(transition) {
      const model = this.currentModel;
      if (!model) {
        return true;
      }
      if (model.hasDirtyAttributes) {
        if (
          window.confirm(
            'You have unsaved changes. Navigating away will discard these changes. Are you sure you want to discard your changes?'
          )
        ) {
          return true;
        } else {
          transition.abort();
          return false;
        }
      }
      return true;
    },
  },
});
