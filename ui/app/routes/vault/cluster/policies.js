/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import ClusterBaseRoute from '../cluster-base';

const ALLOWED_TYPES = ['acl', 'egp', 'rgp'];

export default ClusterBaseRoute.extend({
  version: service(),

  model(params) {
    const policyType = params.type;
    if (!ALLOWED_TYPES.includes(policyType)) {
      return this.transitionTo(this.routeName, ALLOWED_TYPES[0]);
    }
    return {};
  },
});
