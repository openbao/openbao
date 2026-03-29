/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { singularize } from 'ember-inflector';
import { inject as service } from '@ember/service';

export default Route.extend({
  store: service(),

  model() {
    const { item_type: itemType } = this.paramsFor('vault.cluster.access.method.item');
    const methodModel = this.modelFor('vault.cluster.access.method');
    const { type } = methodModel;
    const { path: method } = this.paramsFor('vault.cluster.access.method');
    const modelType = `generated-${singularize(itemType)}-${type}`;
    return this.store.createRecord(modelType, {
      itemType,
      method,
      adapterOptions: { path: `${method}/${itemType}` },
    });
  },

  setupController(controller) {
    this._super(...arguments);
    const { item_type: itemType } = this.paramsFor('vault.cluster.access.method.item');
    const { path: method } = this.paramsFor('vault.cluster.access.method');
    controller.set('itemType', singularize(itemType));
    controller.set('mode', 'create');
    controller.set('method', method);
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
