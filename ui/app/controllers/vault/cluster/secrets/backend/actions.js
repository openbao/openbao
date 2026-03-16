/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { computed } from '@ember/object';

export default Controller.extend({
  queryParams: {
    selectedAction: 'action',
  },

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
    refresh: function () {
      // closure actions don't bubble to routes,
      // so we have to manually bubble here
      this.send('refreshModel');
    },
  },
});
