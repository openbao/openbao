/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';
export default class KubernetesRoleCredentialsRoute extends Route {
  @service secretMountPath;

  model() {
    return {
      roleName: this.paramsFor('roles.role').name,
      backend: this.secretMountPath.get(),
    };
  }

  setupController(controller, resolvedModel) {
    super.setupController(controller, resolvedModel);

    controller.breadcrumbs = [
      { label: resolvedModel.backend, route: 'overview', models: [resolvedModel.backend] },
      { label: 'roles', route: 'roles', models: [resolvedModel.backend] },
      {
        label: resolvedModel.roleName,
        route: 'roles.role.details',
        models: [resolvedModel.backend, resolvedModel.roleName],
      },
      { label: 'credentials' },
    ];
  }
}
