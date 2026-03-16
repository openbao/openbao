/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { computed } from '@ember/object';
import escapeStringRegexp from 'escape-string-regexp';
import commonPrefix from 'core/utils/common-prefix';

export default Controller.extend({
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
  },
});
