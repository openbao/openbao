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

export default Controller.extend({
  navToNearestAncestor: task(function* (key) {
    const ancestors = utils.ancestorKeysForKey(key);
    let errored = false;
    let nearest = ancestors.pop();
    while (nearest) {
      try {
        const transition = this.transitionToRoute('vault.cluster.secrets.backend.list', nearest);
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
    yield this.transitionToRoute('vault.cluster.secrets.backend.list-root');
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
          this.send('reload');
          if (type === 'secret') {
            this.navToNearestAncestor.perform(name);
          }
        })
        .catch((e) => {
          const error = e.errors ? e.errors.join('. ') : e.message;
          this.flashMessages.danger(error);
        });
    },
  },
});
