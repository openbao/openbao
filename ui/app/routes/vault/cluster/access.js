/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { computed } from '@ember/object';
import Route from '@ember/routing/route';
import ClusterRoute from 'vault/mixins/cluster-route';
import { inject as service } from '@ember/service';

export default Route.extend(ClusterRoute, {
  store: service(),
  modelTypes: computed(function () {
    return ['capabilities', 'identity/group', 'identity/group-alias', 'identity/alias'];
  }),

  deactivate() {
    this._super(...arguments);
    this.modelTypes.forEach((type) => {
      this.store.unloadAll(type);
    });
  },

  model() {
    return {};
  },
});
