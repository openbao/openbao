/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { task } from 'ember-concurrency';
import { inject as service } from '@ember/service';
import removeRecord from 'vault/utils/remove-record';

export default Controller.extend({
  store: service(),
  showRoute: 'vault.cluster.access.identity.show',
  showTab: 'details',
  navAfterSave: task(function* ({ saveType, model }) {
    const isDelete = saveType === 'delete';
    const type = model.get('identityType');
    const listRoutes = {
      'entity-alias': 'vault.cluster.access.identity.aliases.index',
      'group-alias': 'vault.cluster.access.identity.aliases.index',
      group: 'vault.cluster.access.identity.index',
      entity: 'vault.cluster.access.identity.index',
    };
    const routeName = listRoutes[type];
    if (!isDelete) {
      yield this.transitionToRoute(this.showRoute, model.id, this.showTab);
      return;
    }
    yield this.transitionToRoute(routeName);
  }),

  cleanupModel() {
    const model = this.model;

    if (!model) {
      return;
    }

    if (model.isSaving || model.isDestroyed || model.isDestroying) {
      return;
    }

    // controllers are singletons — always unset
    this.model = null;

    if (typeof model.unloadRecord === 'function') {
      removeRecord(this.store, model);
      model.destroy();
    }
  },
});
