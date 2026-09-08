/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { or } from '@ember/object/computed';
import { computed } from '@ember/object';
import { inject as service } from '@ember/service';
import Controller from '@ember/controller';
import utils from 'vault/lib/key-utils';
import { task } from 'ember-concurrency';
import escapeStringRegexp from 'escape-string-regexp';
import commonPrefix from 'core/utils/common-prefix';
import transitionToSafe from 'vault/utils/transition-to-safe';

export default Controller.extend({
  router: service(),
  store: service(),
  navToNearestAncestor: task(function* (key) {
    const ancestors = utils.ancestorKeysForKey(key);
    let errored = false;
    let nearest = ancestors.pop();
    // Force a refetch of the current folder when navigating to the same
    // route/params after a deletion: ember-data 4.12 keeps deleted records
    // in an already-cached lazy page, so a 404-folder would still appear to
    // contain the deleted key. Only KV listings are cleared here; non-KV
    // engines list under a different cache key, so clear everything (transit
    // keys can contain '/', so same-route ancestor transitions do happen).
    if (['kv', 'generic', 'cubbyhole'].includes(this.backendType)) {
      this.store.clearDataset('secret');
      this.store.clearDataset('secret-v2');
    } else {
      this.store.clearAllDatasets();
    }
    while (nearest) {
      try {
        const transition = this.router.transitionTo('vault.cluster.secrets.backend.list', nearest);
        transition.data.isDeletion = true;
        yield transition.promise;
      } catch {
        // in the route error event handler, we're only throwing when it's a 404,
        // other errors will be in the route and will not be caught, so the task will complete
        errored = true;
        nearest = ancestors.pop();
      } finally {
        if (!errored) {
          nearest = null;
          // eslint-disable-next-line
          return;
        }
        errored = false;
      }
    }
    // A root-level key has no ancestor to navigate to. If we're deleting it
    // while already on the list page, transitioning to list-root is a
    // same-route no-op that won't refetch, leaving the stale entry in the
    // (possibly non-KV, e.g. ssh/transit/aws) listing. Force a reload instead,
    // which clears every dataset and re-runs the model hook.
    if (this.router.currentRouteName === 'vault.cluster.secrets.backend.list-root') {
      this.send('reload');
    } else {
      yield transitionToSafe(this.router, 'vault.cluster.secrets.backend.list-root');
    }
  }),

  flashMessages: service(),
  queryParams: ['page', 'pageFilter', 'tab'],
  page: 1,
  pageFilter: null,
  filter: null,
  filterFocused: false,

  isLoading: false,

  filterMatchesKey: computed('filter', 'model', 'model.[]', function () {
    const { filter, model: content } = this;
    return !!(content.length && content.find((x) => x.id === filter));
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

  tab: '',

  filterIsFolder: computed('filter', function () {
    return !!utils.keyIsFolder(this.filter);
  }),

  isConfigurableTab: or('isCertTab', 'isConfigure'),

  backendCrumb: computed('backend', function () {
    const backend = this.backend;

    return {
      label: backend,
      text: backend,
      path: 'vault.cluster.secrets.backend.list-root',
      model: backend,
    };
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

    chooseAction(action) {
      this.set('selectedAction', action);
    },

    toggleZeroAddress(item, backend) {
      item.toggleProperty('zeroAddress');
      this.set('loading-' + item.id, true);
      backend
        .saveZeroAddressConfig()
        .catch((e) => {
          item.set('zeroAddress', false);
          this.flashMessages.danger(e.message);
        })
        .finally(() => {
          this.set('loading-' + item.id, false);
        });
    },

    delete(item, type) {
      const name = item.id;
      item
        .destroyRecord()
        .then(() => {
          this.flashMessages.success(`${name} was successfully deleted.`);
          if (type === 'secret') {
            this.navToNearestAncestor.perform(name);
          } else {
            this.send('reload');
          }
        })
        .catch((e) => {
          const error = e.errors ? e.errors.join('. ') : e.message;
          this.flashMessages.danger(error);
        });
    },
  },
});
