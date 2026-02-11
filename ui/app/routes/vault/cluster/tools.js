/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import ClusterBaseRoute from '../cluster-base';

export default ClusterBaseRoute.extend({
  model() {
    return this.modelFor('vault.cluster');
  },
});
