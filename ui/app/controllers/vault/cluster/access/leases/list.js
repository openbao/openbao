/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import { computed } from '@ember/object';
import Controller, { inject as controller } from '@ember/controller';
import utils from 'vault/lib/key-utils';
import escapeStringRegexp from 'escape-string-regexp';
import commonPrefix from 'core/utils/common-prefix';

export default Controller.extend({
  flashMessages: service(),
  store: service(),
  clusterController: controller('vault.cluster'),

  backendCrumb: computed('clusterController.model.name', function () {
    return {
      label: 'leases',
      text: 'leases',
      path: 'vault.cluster.access.leases.list-root',
      model: this.clusterController.model.name,
    };
  }),

  queryParams: {
    page: 'page',
    pageFilter: 'pageFilter',
  },

  page: 1,
  pageFilter: null,
  filter: null,
  filterFocused: false,

  isLoading: false,

  filterIsFolder: computed('filter', function () {
    return !!utils.keyIsFolder(this.filter);
  }),

  filterMatchesKey: computed('filter', 'model', 'model.[]', function () {
    const { filter, model: content } = this;
    return !!(content.length && content.findBy('id', filter));
  }),

  firstPartialMatch: computed('filter', 'model', 'model.[]', 'filterMatchesKey', function () {
    const { filter, filterMatchesKey, model: content } = this;
    const re = new RegExp('^' + escapeStringRegexp(filter));
    const matchSet = content.filter((key) => re.test(key.id));
    const match = matchSet[0];

    if (filterMatchesKey || !match) {
      return null;
    }

    const sharedPrefix = commonPrefix(content);
    // if we already are filtering the prefix, then next we want
    // the exact match
    if (filter === sharedPrefix || matchSet.length === 1) {
      return match;
    }
    return { id: sharedPrefix };
  }),

  emptyTitle: computed('baseKey.id', 'filter', 'filterIsFolder', function () {
    const id = this.baseKey.id;
    const filter = this.filter;
    if (id === '') {
      return 'There are currently no leases.';
    }
    if (this.filterIsFolder) {
      if (filter === id) {
        return `There are no leases under &quot;${filter}&quot;.`;
      } else {
        return `We couldn't find a prefix matching &quot;${filter}&quot;.`;
      }
    }
    return '';
  }),

  actions: {
    setFilter(val) {
      this.set('filter', val);
    },

    setFilterFocus(bool) {
      this.set('filterFocused', bool);
    },

    refresh() {
      // bubble to the list-route
      this.send('reload');
    },

    revokePrefix(prefix, isForce) {
      const adapter = this.store.adapterFor('lease');
      const method = isForce ? 'forceRevokePrefix' : 'revokePrefix';
      const fn = adapter[method];
      fn.call(adapter, prefix)
        .then(() => {
          return this.transitionToRoute('vault.cluster.access.leases.list-root').then(() => {
            this.flashMessages.success(`All of the leases under ${prefix} will be revoked.`);
          });
        })
        .catch((e) => {
          const errString = e.errors.join('.');
          this.flashMessages.danger(
            `There was an error attempting to revoke the prefix: ${prefix}. ${errString}.`
          );
        });
    },
  },
});
