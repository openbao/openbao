/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';
import ClusterRoute from 'vault/mixins/cluster-route';

const ALLOWED_TYPES = ['acl', 'egp', 'rgp'];

export default Route.extend(ClusterRoute, {
  version: service(),
  model(params) {
    const policyType = params.type;
    if (!ALLOWED_TYPES.includes(policyType)) {
      return this.transitionTo('vault.cluster.policies', ALLOWED_TYPES[0]);
    }
    if (policyType !== 'acl') {
      return this.transitionTo('vault.cluster.policies', policyType);
    }
    return {};
  },
});
