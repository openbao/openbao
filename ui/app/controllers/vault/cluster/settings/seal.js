/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Controller from '@ember/controller';

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
          return this.router.transitionTo('vault.cluster.unseal');
        })
        .catch((error) => {
          if (error?.name !== 'TransitionAborted') throw error;
        });
    },
  },
});
