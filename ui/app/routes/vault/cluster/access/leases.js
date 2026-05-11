/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import ClusterBaseRoute from '../../cluster-base';
import { inject as service } from '@ember/service';

export default ClusterBaseRoute.extend({
  store: service(),

  model() {
    return this.store.findRecord('capabilities', 'sys/leases/lookup/');
  },
});
