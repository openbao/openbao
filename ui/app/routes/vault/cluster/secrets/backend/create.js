/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default Route.extend({
  router: service(),
  beforeModel() {
    const { secret, initialKey } = this.paramsFor(this.routeName);
    const qp = initialKey || secret;
    return this.router.transitionTo('vault.cluster.secrets.backend.create-root', {
      queryParams: { initialKey: qp },
    });
  },
});
