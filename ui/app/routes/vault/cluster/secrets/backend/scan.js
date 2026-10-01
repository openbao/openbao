// SPDX-License-Identifier: MPL-2.0

import ListRoute from './list';

export default ListRoute.extend({
  controllerName: 'vault/cluster/secrets/backend/scan',
  isScan: true,

  beforeModel() {
    const secret = this.secretParam();
    const type = this.modelFor('vault.cluster.secrets.backend')?.engineType;

    if (type && !['kv', 'generic', 'cubbyhole'].includes(type)) {
      return this.router.transitionTo('vault.cluster.secrets.backend.list-root');
    }
    if (this.routeName === 'vault.cluster.secrets.backend.scan' && !secret.endsWith('/')) {
      return this.router.replaceWith('vault.cluster.secrets.backend.scan', secret + '/');
    }
    return this._super(...arguments);
  },
});
