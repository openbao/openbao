/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { singularize } from 'ember-inflector';
import { inject as service } from '@ember/service';

export default Route.extend({
  store: service(),

  model(params) {
    const id = params.item_id;
    const { item_type: itemType } = this.paramsFor('vault.cluster.access.method.item');
    const methodModel = this.modelFor('vault.cluster.access.method');
    const modelType = `generated-${singularize(itemType)}-${methodModel.type}`;
    return this.store.queryRecord(modelType, { id, authMethodPath: methodModel.id });
  },

  setupController(controller) {
    this._super(...arguments);
    const { item_type: itemType } = this.paramsFor('vault.cluster.access.method.item');
    controller.set('itemType', singularize(itemType));
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
