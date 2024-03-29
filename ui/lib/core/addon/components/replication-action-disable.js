/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Actions from 'core/components/replication-actions-single';
import layout from '../templates/components/replication-action-disable';

export default Actions.extend({
  layout,
  tagName: '',

  actions: {
    onSubmit(replicationMode, clusterMode, evt) {
      // No data is submitted for disable request
      return this.onSubmit(replicationMode, clusterMode, null, evt);
    },
  },
});
