/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Controller from '@ember/controller';
import { supportedSecretBackends } from 'vault/helpers/supported-secret-backends';
import { allEngines } from 'vault/helpers/mountable-secret-engines';
import { action } from '@ember/object';
import transitionToSafe from 'vault/utils/transition-to-safe';

const SUPPORTED_BACKENDS = supportedSecretBackends();

export default class MountSecretBackendController extends Controller {
  @service router;

  @action
  onMountSuccess(type, path) {
    let route;
    if (SUPPORTED_BACKENDS.includes(type)) {
      const engineInfo = allEngines().find((x) => x.type === type);
      if (engineInfo?.engineRoute) {
        route = [`vault.cluster.secrets.backend.${engineInfo.engineRoute}`, path];
      } else {
        const queryParams = engineInfo?.routeQueryParams || {};
        route = ['vault.cluster.secrets.backend.index', path, { queryParams }];
      }
    } else {
      route = ['vault.cluster.secrets.backends'];
    }
    // transitionToSafe resolves on the redirect abort, before the target
    // route's model loads; the caller has no side effects after that
    return transitionToSafe(this.router, ...route);
  }
}
