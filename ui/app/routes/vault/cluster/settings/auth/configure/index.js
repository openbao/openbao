/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { tabsForAuthSection } from 'vault/helpers/tabs-for-auth-section';
import { inject as service } from '@ember/service';

export default Route.extend({
  router: service(),
  beforeModel() {
    const model = this.modelFor('vault.cluster.settings.auth.configure');
    const section = tabsForAuthSection([model])[0].routeParams.lastObject;
    return this.router.transitionTo('vault.cluster.settings.auth.configure.section', section);
  },
});
