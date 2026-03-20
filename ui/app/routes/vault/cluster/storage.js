/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import ClusterBaseRoute from '../cluster-base';
import { inject as service } from '@ember/service';

export default ClusterBaseRoute.extend({
  store: service(),

  model() {
    // findAll method will return all records in store as well as response from server
    // when removing a peer via the cli, stale records would continue to appear until refresh
    // query method will only return records from response
    return this.store.query('server', {});
  },

  actions: {
    doRefresh() {
      this.refresh();
    },
  },
});
