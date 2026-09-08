/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default class KubernetesRolesCreateRoute extends Route {
  @service store;
  @service secretMountPath;

  model() {
    const backend = this.secretMountPath.get();
    return this.store.createRecord('kubernetes/role', { backend });
  }

  setupController(controller, resolvedModel) {
    super.setupController(controller, resolvedModel);

    controller.breadcrumbs = [
      { label: resolvedModel.backend, route: 'overview', models: [resolvedModel.backend] },
      { label: 'roles', route: 'roles', models: [resolvedModel.backend] },
      { label: 'create' },
    ];
  }
}
