/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { inject as service } from '@ember/service';

export default Controller.extend({
  router: service(),
  actions: {
    transitionToCluster() {
      return this.model
        .reload()
        .then(() => {
          return this.router.transitionTo('vault.cluster', this.model.name);
        })
        .catch((error) => {
          if (error?.name !== 'TransitionAborted') throw error;
        });
    },

    isUnsealed(data) {
      return data.sealed === false;
    },
  },
});
