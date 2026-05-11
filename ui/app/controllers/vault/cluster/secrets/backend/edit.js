/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller, { inject as controller } from '@ember/controller';
import { computed } from '@ember/object';

export default Controller.extend({
  backendController: controller('vault.cluster.secrets.backend'),
  queryParams: ['version', 'itemType'],
  version: '',
  itemType: '',

  backendCrumb: computed('backend', function () {
    const backend = this.backend;

    return {
      label: backend,
      text: backend,
      path: 'vault.cluster.secrets.backend.list-root',
      model: backend,
    };
  }),

  reset() {
    this.set('version', '');
    this.set('itemType', '');
  },
  actions: {
    refresh: function () {
      // closure actions don't bubble to routes,
      // so we have to manually bubble here
      this.send('refreshModel');
    },

    toggleAdvancedEdit(bool) {
      this.set('preferAdvancedEdit', bool);
      this.backendController.set('preferAdvancedEdit', bool);
    },
  },
});
