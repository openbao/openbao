/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import EditBase from './secret-edit';
import utils from 'vault/lib/key-utils';
import { inject as service } from '@ember/service';

export default EditBase.extend({
  router: service(),
  queryParams: {
    selectedAction: {
      replace: true,
    },
  },

  templateName: 'vault/cluster/secrets/backend/transitActionsLayout',

  beforeModel() {
    const { secret } = this.paramsFor(this.routeName);
    const parentKey = utils.parentKeyForKey(secret);
    const { backend } = this.paramsFor('vault.cluster.secrets.backend');
    if (this.backendType(backend) !== 'transit') {
      if (parentKey) {
        return this.router.transitionTo('vault.cluster.secrets.backend.show', parentKey);
      } else {
        return this.router.transitionTo('vault.cluster.secrets.backend.show-root');
      }
    }
  },
  setupController(controller, model) {
    this._super(...arguments);
    const { selectedAction } = this.paramsFor(this.routeName);
    controller.set('selectedAction', selectedAction || model.secret.supportedActions[0]);
  },
});
