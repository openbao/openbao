/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import RESTSerializer, { EmbeddedRecordsMixin } from '@ember-data/serializer/rest';
import { assign } from '@ember/polyfills';
import { decamelize } from '@ember/string';

export default RESTSerializer.extend(EmbeddedRecordsMixin, {
  keyForAttribute: function (attr) {
    return decamelize(attr);
  },

  attrs: {
    nodes: { embedded: 'always' },
  },

  normalize(modelClass, data) {
    return this._super(modelClass, data);
  },

  pushPayload(store, payload) {
    const transformedPayload = this.normalizeResponse(
      store,
      store.modelFor('cluster'),
      payload,
      null,
      'findAll'
    );
    return store.push(transformedPayload);
  },

  normalizeResponse(store, primaryModelClass, payload, id, requestType) {
    // FIXME when multiple clusters lands
    const transformedPayload = {
      clusters: assign({ id: '1' }, payload.data || payload),
    };

    return this._super(store, primaryModelClass, transformedPayload, id, requestType);
  },
});
