/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';

export default Route.extend({
  store: service(),
  version: service(),

  model() {
    const policyType = this.policyType();
    if (policyType !== 'acl') {
      return this.transitionTo('vault.cluster.policies', policyType);
    }
    return this.store.createRecord(`policy/${policyType}`, {});
  },

  setupController(controller) {
    this._super(...arguments);
    controller.set('policyType', this.policyType());
  },

  policyType() {
    return this.paramsFor('vault.cluster.policies').type;
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
