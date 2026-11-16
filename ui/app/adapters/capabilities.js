/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import AdapterError, { ForbiddenError, NotFoundError } from '@ember-data/adapter/error';
import { set } from '@ember/object';
import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  pathForType() {
    return 'capabilities-self';
  },

  findRecord(store, type, id) {
    return this.ajax(this.buildURL(type), 'POST', { data: { paths: [id] } }).catch((e) => {
      if (e instanceof AdapterError) {
        set(e, 'policyPath', 'sys/capabilities-self');
      }
      // catch 403 and 404 errors
      if (e instanceof ForbiddenError || e instanceof NotFoundError) {
        return { data: { path: id } };
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
