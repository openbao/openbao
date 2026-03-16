/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import { alias } from '@ember/object/computed';
import Controller from '@ember/controller';
import removeRecord from 'vault/utils/remove-record';

export default Controller.extend({
  namespaceService: service('namespace'),
  accessibleNamespaces: alias('namespaceService.accessibleNamespaces'),
  currentNamespace: alias('namespaceService.path'),
  store: service(),

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
  actions: {
    refreshNamespaceList() {
      // fetch new namespaces for the namespace picker
      this.namespaceService.findNamespacesForUser.perform();
      this.send('reload');
    },
  },
});
