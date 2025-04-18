/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Service, { inject as service } from '@ember/service';
import { task } from 'ember-concurrency';

const API_PATHS = {
  access: {
    methods: 'sys/auth',
    mfa: 'identity/mfa/method',
    oidc: 'identity/oidc/client',
    entities: 'identity/entity/id',
    groups: 'identity/group/id',
    leases: 'sys/leases/lookup',
    namespaces: 'sys/namespaces',
    'control-groups': 'sys/control-group/',
  },
  policies: {
    acl: 'sys/policies/acl',
  },
  tools: {
    wrap: 'sys/wrapping/wrap',
    lookup: 'sys/wrapping/lookup',
    unwrap: 'sys/wrapping/unwrap',
    rewrap: 'sys/wrapping/rewrap',
    random: 'sys/tools/random',
    hash: 'sys/tools/hash',
  },
  status: {
    license: 'sys/license',
    seal: 'sys/seal',
    raft: 'sys/storage/raft/configuration',
  },
  clients: {
    activity: 'sys/internal/counters/activity',
    config: 'sys/internal/counters/config',
  },
};

const API_PATHS_TO_ROUTE_PARAMS = {
  'sys/auth': { route: 'vault.cluster.access.methods', models: [] },
  'identity/entity/id': { route: 'vault.cluster.access.identity', models: ['entities'] },
  'identity/group/id': { route: 'vault.cluster.access.identity', models: ['groups'] },
  'sys/leases/lookup': { route: 'vault.cluster.access.leases', models: [] },
  'sys/namespaces': { route: 'vault.cluster.access.namespaces', models: [] },
  'sys/control-group/': { route: 'vault.cluster.access.control-groups', models: [] },
  'identity/mfa/method': { route: 'vault.cluster.access.mfa', models: [] },
  'identity/oidc/client': { route: 'vault.cluster.access.oidc', models: [] },
};

/*
  The Permissions service is used to gate top navigation and sidebar items.
  It fetches a users' policy from the resultant-acl endpoint and stores their
  allowed exact and glob paths as state. It also has methods for checking whether
  a user has permission for a given path.
*/

export default Service.extend({
  exactPaths: null,
  globPaths: null,
  canViewAll: null,
  store: service(),
  auth: service(),
  namespace: service(),

  getPaths: task(function* () {
    if (this.paths) {
      return;
    }

    try {
      const resp = yield this.store.adapterFor('permissions').query();
      this.setPaths(resp);
      return;
    } catch {
      // If no policy can be found, default to showing all nav items.
      this.set('canViewAll', true);
    }
  }),

  setPaths(resp) {
    this.set('exactPaths', resp.data.exact_paths);
    this.set('globPaths', resp.data.glob_paths);
    this.set('canViewAll', resp.data.root);
  },

  reset() {
    this.set('exactPaths', null);
    this.set('globPaths', null);
    this.set('canViewAll', null);
  },

  hasNavPermission(navItem, routeParams, requireAll) {
    if (routeParams) {
      // check that the user has permission to access all (requireAll = true) or any of the routes when array is passed
      // useful for hiding nav headings when user does not have access to any of the links
      const params = Array.isArray(routeParams) ? routeParams : [routeParams];
      const evalMethod = !Array.isArray(routeParams) || requireAll ? 'every' : 'some';
      return params[evalMethod]((param) => {
        // viewing the entity and groups pages require the list capability, while the others require the default, which is anything other than deny
        const capability = param === 'entities' || param === 'groups' ? ['list'] : [null];
        return this.hasPermission(API_PATHS[navItem][param], capability);
      });
    }
    return Object.values(API_PATHS[navItem]).some((path) => this.hasPermission(path));
  },

  navPathParams(navItem) {
    const path = Object.values(API_PATHS[navItem]).find((path) => this.hasPermission(path));
    if (['policies', 'tools'].includes(navItem)) {
      return { models: [path.split('/').lastObject] };
    }

    return API_PATHS_TO_ROUTE_PARAMS[path];
  },

  pathNameWithNamespace(pathName) {
    const namespace = this.namespace.path;
    if (namespace) {
      return `${namespace}/${pathName}`;
    } else {
      return pathName;
    }
  },

  hasPermission(pathName, capabilities = [null]) {
    const path = this.pathNameWithNamespace(pathName);

    if (this.canViewAll) {
      return true;
    }

    return capabilities.every(
      (capability) =>
        this.hasMatchingExactPath(path, capability) || this.hasMatchingGlobPath(path, capability)
    );
  },

  hasMatchingExactPath(pathName, capability) {
    const exactPaths = this.exactPaths;
    if (exactPaths) {
      const prefix = Object.keys(exactPaths).find((path) => path.startsWith(pathName));
      const hasMatchingPath = prefix && !this.isDenied(exactPaths[prefix]);

      if (prefix && capability) {
        return this.hasCapability(exactPaths[prefix], capability) && hasMatchingPath;
      }

      return hasMatchingPath;
    }
    return false;
  },

  hasMatchingGlobPath(pathName, capability) {
    const globPaths = this.globPaths;
    if (globPaths) {
      const matchingPath = Object.keys(globPaths).find((k) => {
        return pathName.includes(k) || pathName.includes(k.replace(/\/$/, ''));
      });
      const hasMatchingPath =
        (matchingPath && !this.isDenied(globPaths[matchingPath])) ||
        Object.prototype.hasOwnProperty.call(globPaths, '');

      if (matchingPath && capability) {
        return this.hasCapability(globPaths[matchingPath], capability) && hasMatchingPath;
      }

      return hasMatchingPath;
    }
    return false;
  },

  hasCapability(path, capability) {
    return path.capabilities.includes(capability);
  },

  isDenied(path) {
    return path.capabilities.includes('deny');
  },
});
