/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { inject as service } from '@ember/service';

export default Controller.extend({
  router: service(),
  actions: {
    lookupLease(id) {
      this.router.transitionTo('vault.cluster.access.leases.show', id);
    },
  },
});
