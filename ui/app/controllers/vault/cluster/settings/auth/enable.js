/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { inject as service } from '@ember/service';

export default Controller.extend({
  router: service(),
  actions: {
    onMountSuccess: function (type, path) {
      const transition = this.router.transitionTo('vault.cluster.settings.auth.configure', path);
      return transition.followRedirects();
    },
  },
});
