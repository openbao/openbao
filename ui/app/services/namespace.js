/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { equal } from '@ember/object/computed';
import { computed } from '@ember/object';
import Service, { inject as service } from '@ember/service';
import { task } from 'ember-concurrency';

const ROOT_NAMESPACE = '';
export default Service.extend({
  store: service(),
  auth: service(),

  // Safe computed property for userRootNamespace
  userRootNamespace: computed('auth.authData.userRootNamespace', function () {
    return this.auth?.authData?.userRootNamespace || '';
  }),

  //populated by the query param on the cluster route
  path: '',
  // list of namespaces available to the current user under the
  // current namespace
  accessibleNamespaces: null,

  inRootNamespace: equal('path', ROOT_NAMESPACE),

  setNamespace(path) {
    if (!path) {
      this.set('path', '');
      return;
    }
    this.set('path', path);
  },

  findNamespacesForUser: task(function* () {
    // uses the adapter and the raw response here since
    // models get wiped when switching namespaces and we
    // want to keep track of these separately
    const store = this.store;
    const adapter = store.adapterFor('namespace');

    // Safe access to userRootNamespace using ES5 getter
    const userRoot = this.userRootNamespace;

    // Use current namespace path, fallback to userRoot for initial load
    const currentNamespace = this.path || userRoot || '';

    try {
      const ns = yield adapter.findAll(store, 'namespace', null, {
        adapterOptions: {
          forUser: true,
          namespace: currentNamespace,
        },
      });
      const keys = ns.data.keys || [];

      this.set(
        'accessibleNamespaces',
        keys.map((n) => {
          let fullNS = n;
          // if we're in a namespace, construct full paths
          if (currentNamespace) {
            fullNS = `${currentNamespace}/${n}`;
          }
          return fullNS.replace(/\/$/, '');
        })
      );
    } catch {
      //do nothing here
    }
  }).drop(),

  reset() {
    this.set('accessibleNamespaces', null);
  },
});
