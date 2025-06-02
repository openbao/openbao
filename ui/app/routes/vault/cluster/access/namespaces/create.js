/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';
import UnloadModel from 'vault/mixins/unload-model-route';

export default class CreateRoute extends Route.extend(UnloadModel) {
  @service store;
  @service version;

  beforeModel() {
    return this.version.fetchFeatures().then(() => {
      return super.beforeModel(...arguments);
    });
  }

  model() {
    return this.store.createRecord('namespace');
  }
}
