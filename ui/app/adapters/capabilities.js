/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import AdapterError from '@ember-data/adapter/error';
import { set } from '@ember/object';
import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  pathForType() {
    return 'capabilities-self';
  },

  // the namespace being browsed, relative to the one the token was issued in
  relativeNamespace() {
    const { userRootNamespace, path } = this.namespaceService;
    if (!userRootNamespace) {
      return path;
    }
    if (path === userRootNamespace) {
      return '';
    }
    return path.startsWith(`${userRootNamespace}/`) ? path.slice(userRootNamespace.length + 1) : path;
  },

  findRecord(store, type, id) {
    const relativeNamespace = this.relativeNamespace();
    const prefix = relativeNamespace ? `${relativeNamespace}/` : '';

    return this.ajax(this.buildURL(type), 'POST', {
      namespace: this.namespaceService.userRootNamespace,
      data: { paths: [`${prefix}${id}`] },
    }).catch((e) => {
      if (e instanceof AdapterError) {
        set(e, 'policyPath', 'sys/capabilities-self');
      }
      throw e;
    });
  },

  queryRecord(store, type, query) {
    const { id } = query;
    if (!id) {
      return;
    }
    return this.findRecord(store, type, id).then((resp) => {
      resp.path = id;
      return resp;
    });
  },
});
