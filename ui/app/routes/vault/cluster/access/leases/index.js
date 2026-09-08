/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default Route.extend({
  router: service(),

  beforeModel(transition) {
    if (this.modelFor('vault.cluster.access.leases').canList && transition.targetName === this.routeName) {
      return this.router.replaceWith('vault.cluster.access.leases.list-root');
    } else {
      return;
    }
  },
});
