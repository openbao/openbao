/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Controller from '@ember/controller';
import transitionToSafe from 'vault/utils/transition-to-safe';

export default Controller.extend({
  auth: service(),
  router: service(),

  actions: {
    seal() {
      return this.model.cluster.store
        .adapterFor('cluster')
        .seal()
        .then(() => {
          this.model.cluster.leaderNode.set('sealed', true);
          this.auth.deleteCurrentToken();
          return transitionToSafe(this.router, 'vault.cluster.unseal');
        });
    },
  },
});
