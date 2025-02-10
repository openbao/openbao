/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { attr, hasMany } from '@ember-data/model';
import { inject as service } from '@ember/service';
import { alias, equal, gte, not } from '@ember/object/computed';
import { computed } from '@ember/object';

export default Model.extend({
  version: service(),

  nodes: hasMany('nodes', { async: false }),
  name: attr('string'),
  status: attr('string'),
  standby: attr('boolean'),
  type: attr('string'),
  license: attr('object'),

  needsInit: computed('nodes', 'nodes.@each.initialized', function () {
    // needs init if no nodes are initialized
    return this.nodes.isEvery('initialized', false);
  }),

  unsealed: computed('nodes', 'nodes.{[],@each.sealed}', function () {
    // unsealed if there's at least one unsealed node
    return !!this.nodes.findBy('sealed', false);
  }),

  sealed: not('unsealed'),

  leaderNode: computed('nodes', 'nodes.[]', function () {
    const nodes = this.nodes;
    if (nodes.get('length') === 1) {
      return nodes.get('firstObject');
    } else {
      return nodes.findBy('isLeader');
    }
  }),

  sealThreshold: alias('leaderNode.sealThreshold'),
  sealProgress: alias('leaderNode.progress'),
  sealType: alias('leaderNode.type'),
  storageType: alias('leaderNode.storageType'),
  hasProgress: gte('sealProgress', 1),
  usingRaft: equal('storageType', 'raft'),

  //replication mode - will only ever be 'unsupported'
  //otherwise the particular mode will have the relevant mode attr through replication-attributes
  mode: attr('string'),
});
