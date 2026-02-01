/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Controller from '@ember/controller';
import { computed } from '@ember/object';
import escapeStringRegexp from 'escape-string-regexp';
import commonPrefix from 'core/utils/common-prefix';

export default Controller.extend({
  flashMessages: service(),
  queryParams: {
    page: 'page',
    pageFilter: 'pageFilter',
  },

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

    delete(model) {
      const type = model.get('identityType');
      const id = model.id;
      return model
        .destroyRecord()
        .then(() => {
          this.send('reload');
          this.flashMessages.success(`Successfully deleted ${type}: ${id}`);
        })
        .catch((e) => {
          this.flashMessages.success(
            `There was a problem deleting ${type}: ${id} - ${e.errors.join(' ') || e.message}`
          );
        });
    },

    toggleDisabled(model) {
      const action = model.get('disabled') ? ['enabled', 'enabling'] : ['disabled', 'disabling'];
      const type = model.get('identityType');
      const id = model.id;
      model.toggleProperty('disabled');

      model
        .save()
        .then(() => {
          this.flashMessages.success(`Successfully ${action[0]} ${type}: ${id}`);
        })
        .catch((e) => {
          this.flashMessages.success(
            `There was a problem ${action[1]} ${type}: ${id} - ${e.errors.join(' ') || e.message}`
          );
        });
    },
    reloadRecord(model) {
      model.reload();
    },
  },
});
