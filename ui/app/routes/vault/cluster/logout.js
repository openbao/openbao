/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Ember from 'ember';
import { computed } from '@ember/object';
import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';

export default Route.extend({
  store: service(),
  auth: service(),
  flashMessages: service(),
  console: service(),
  permissions: service(),
  namespaceService: service('namespace'),
  router: service(),

  modelTypes: computed(function () {
    return ['secret', 'secret-engine'];
  }),

  beforeModel({ to: { queryParams } }) {
    const authType = this.auth.getAuthType();
    // Look up namespace at login
    const userRootNamespace = this.auth.authData?.userRootNamespace;
    // Prefilled namespace is namespace at previous login, if found. Else, current namespace.
    const ns = typeof userRootNamespace === 'string' ? userRootNamespace : this.namespaceService.path;
    this.auth.deleteCurrentToken();
    this.namespaceService.reset();
    this.console.set('isOpen', false);
    this.console.clearLog(true);
    this.flashMessages.clearMessages();
    this.permissions.reset();

    queryParams.with = authType;
    if (ns) {
      queryParams.namespace = ns;
    } else {
      delete queryParams.namespace;
    }
    if (Ember.testing) {
      // Don't redirect on the test
      this.router.replaceWith('vault.cluster.auth', { queryParams });
    } else {
      const { cluster_name } = this.paramsFor('vault.cluster');
      location.assign(this.router.urlFor('vault.cluster.auth', cluster_name, { queryParams }));
    }
  },

  deactivate() {
    this._super(...arguments);
    this.modelTypes.forEach((type) => {
      this.store.unloadAll(type);
    });
  },
});
