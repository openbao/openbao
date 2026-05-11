/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';

export default class CreateRoute extends Route.extend({
  store: service('store'),
  resetController(controller, isExiting) {
    this._super(...arguments);

    if (isExiting) {
      controller.cleanupModel?.();
    }
  },
}) {
  @service store;
  @service version;

  model() {
    return this.store.createRecord('namespace');
  }
}
