/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';

export default Controller.extend({
  actions: {
    transitionToCluster() {
      return this.model.reload().then(() => {
        return this.transitionToRoute('vault.cluster', this.model.name);
      });
    },

    isUnsealed(data) {
      return data.sealed === false;
    },
  },
});
