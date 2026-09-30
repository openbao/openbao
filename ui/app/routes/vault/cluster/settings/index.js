/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default Route.extend({
  router: service(),

  beforeModel: function (transition) {
    if (transition.targetName === this.routeName) {
      transition.abort();
      return this.router.replaceWith('vault.cluster.settings.mount-secret-backend');
    }
  },
});
