/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default Route.extend({
  store: service(),

  queryParams: {
    page: {
      refreshModel: true,
    },
    pageFilter: {
      refreshModel: true,
    },
  },

  resetController(controller, isExiting) {
    this._super(...arguments);
    if (isExiting) {
      controller.set('pageFilter', null);
      controller.set('filter', null);
    }
  },

  model(params) {
    const itemType = this.modelFor('vault.cluster.access.identity');
    const modelType = `identity/${itemType}-alias`;
    return this.store
      .lazyPaginatedQuery(modelType, {
        responsePath: 'data.keys',
        page: params.page,
        pageFilter: params.pageFilter,
        sortBy: 'name',
      })
      .catch((err) => {
        if (err.httpStatus === 404) {
          return [];
        } else {
          throw err;
        }
      });
  },

  setupController(controller, resolvedModel) {
    this._super(...arguments);
    const { pageFilter } = this.paramsFor(this.routeName);

    controller.set('identityType', this.modelFor('vault.cluster.access.identity'));
    controller.setProperties({
      filter: pageFilter || '',
      page: resolvedModel?.meta?.currentPage || 1,
    });
  },

  actions: {
    willTransition(transition) {
      window.scrollTo(0, 0);
      if (!transition || transition.targetName !== this.routeName) {
        this.store.clearAllDatasets();
      }
      return true;
    },
    reload() {
      this.store.clearAllDatasets();
      this.refresh();
    },
  },
});
