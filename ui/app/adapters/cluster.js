/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import AdapterError from '@ember-data/adapter/error';
import { inject as service } from '@ember/service';
import { assign } from '@ember/polyfills';
import { hash, resolve } from 'rsvp';
import { pluralize } from 'ember-inflector';

import ApplicationAdapter from './application';

const ENDPOINTS = ['health', 'seal-status', 'tokens', 'token', 'seal', 'unseal', 'init', 'capabilities-self'];

export default ApplicationAdapter.extend({
  namespaceService: service('namespace'),
  shouldBackgroundReloadRecord() {
    return true;
  },

  findRecord(store, type, id, snapshot) {
    const fetches = {
      health: this.health(),
      sealStatus: this.sealStatus().catch((e) => e),
    };
    return hash(fetches).then(({ health, sealStatus }) => {
      let ret = {
        id,
        name: snapshot.attr('name'),
      };
      ret = assign(ret, health);
      if (sealStatus instanceof AdapterError === false) {
        ret = assign(ret, { nodes: [sealStatus] });
      }
      return resolve(ret);
    });
  },

  pathForType(type) {
    return type === 'cluster' ? 'clusters' : pluralize(type);
  },

  health() {
    return this.ajax(this.urlFor('health'), 'GET', {
      data: {
        standbycode: 200,
        sealedcode: 200,
        uninitcode: 200,
        drsecondarycode: 200,
        performancestandbycode: 200,
      },
      unauthenticated: true,
    });
  },

  sealStatus() {
    return this.ajax(this.urlFor('seal-status'), 'GET', { unauthenticated: true });
  },

  seal() {
    return this.ajax(this.urlFor('seal'), 'PUT');
  },

  unseal(data) {
    return this.ajax(this.urlFor('unseal'), 'PUT', {
      data,
      unauthenticated: true,
    });
  },

  initCluster(data) {
    return this.ajax(this.urlFor('init'), 'PUT', {
      data,
      unauthenticated: true,
    });
  },

  authenticate({ backend, data }) {
    const { role, jwt, token, password, username, path } = data;
    const url = this.urlForAuth(backend, username, path);
    const verb = backend === 'token' ? 'GET' : 'POST';
    const options = {
      unauthenticated: true,
    };
    if (backend === 'token') {
      options.headers = {
        'X-Vault-Token': token,
      };
    } else if (backend === 'jwt' || backend === 'oidc') {
      options.data = { role, jwt };
    } else {
      options.data = token ? { token, password } : { password };
    }

    return this.ajax(url, verb, options);
  },

  mfaValidate({ mfa_request_id, mfa_constraints }) {
    const options = {
      data: {
        mfa_request_id,
        mfa_payload: mfa_constraints.reduce((obj, { selectedMethod, passcode }) => {
          let payload = [];
          if (passcode) {
            // duo requires passcode= prepended to the actual passcode
            // this isn't a great UX so we add it behind the scenes to fulfill the requirement
            // check if user added passcode= to avoid duplication
            payload =
              selectedMethod.type === 'duo' && !passcode.includes('passcode=')
                ? [`passcode=${passcode}`]
                : [passcode];
          }
          obj[selectedMethod.id] = payload;
          return obj;
        }, {}),
      },
    };
    return this.ajax('/v1/sys/mfa/validate', 'POST', options);
  },

  urlFor(endpoint) {
    if (!ENDPOINTS.includes(endpoint)) {
      throw new Error(
        `Calls to a ${endpoint} endpoint are not currently allowed in the vault cluster adapater`
      );
    }
    return `${this.buildURL()}/${endpoint}`;
  },

  urlForAuth(type, username, path) {
    const authBackend = type.toLowerCase();
    const authURLs = {
      jwt: 'login',
      oidc: 'login',
      userpass: `login/${encodeURIComponent(username)}`,
      ldap: `login/${encodeURIComponent(username)}`,
      radius: `login/${encodeURIComponent(username)}`,
      token: 'lookup-self',
    };
    const urlSuffix = authURLs[authBackend];
    const urlPrefix = path && authBackend !== 'token' ? path : authBackend;
    if (!urlSuffix) {
      throw new Error(`There is no auth url for ${type}.`);
    }
    return `/v1/auth/${urlPrefix}/${urlSuffix}`;
  },
});
