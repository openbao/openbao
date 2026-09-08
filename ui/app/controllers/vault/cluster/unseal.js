/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { inject as service } from '@ember/service';
import transitionToSafe from 'vault/utils/transition-to-safe';

export default Controller.extend({
  router: service(),
  actions: {
    transitionToCluster() {
      return this.model.reload().then(() => {
        return transitionToSafe(this.router, 'vault.cluster', this.model.name);
      });
    },

    isUnsealed(data) {
      return data.sealed === false;
    },
  },
});
