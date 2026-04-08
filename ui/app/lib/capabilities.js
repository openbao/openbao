/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { belongsTo } from '@ember-data/model';
import { assert } from '@ember/debug';
import { typeOf } from '@ember/utils';
import { isArray } from '@ember/array';

/*
 * capability
 *
 * @param templateFn function that returns the id of the related capability model
 *
 * attach a capability on a model.
 *
 * During deserialization, a relationship will be dynamically created for a capability
 * at the path given by calling `templateFn` on the data.
 *
 * apiPath tagged template function can be used to generate the necessary tempalteFn.
 *
 * @usage
 *
 * class Model extends DS.Model {
 *   @attr backend;
 *   @attr scope;
 *   @capability(apiPath`${'backend'}/scope/${'scope'}/role/${'id'}`)
 *   updatePath;
 * }
 */
export function capability(templateFn) {
  return function (target, name) {
    const cls = target.constructor;
    // Store the templateFn in the list of related capabilities,
    // so we can find them during deserialization
    if (cls.relatedCapabilities == undefined) {
      cls.relatedCapabilities = {};
    }
    cls.relatedCapabilities[name] = templateFn;

    return belongsTo('capabilities', { async: true, inverse: null }).apply(null, arguments);
  };
}

// addCapabilityRelationships is called in the application serializer's
// normalizeResponse hook to add the capabilities relationships to the
// JSON-API document used by Ember Data
// TODO: should this be moved to the serializer folder?
/*
 * relatedCapabilities
 *
 * @param capabilities an object where keys are the names of capabilities, and
 *   values are functions for generating a path from the data.
 *   This should be the `relatedCapabilities` static field from the Model class.
 * @param jsonAPIDoc The JSON API document to deserialize from.
 *
 * add capabilities relationships to the JSON-API document used by Ember Data
 */
export function addCapabilityRelationships(capabilities, jsonAPIDoc) {
  let { data, included } = jsonAPIDoc;
  if (!data) {
    data = jsonAPIDoc;
  }
  if (isArray(data)) {
    const newData = data.map(addCapabilityRelationships.bind(null, capabilities));
    return {
      data: newData,
      included,
    };
  }
  const context = {
    id: data.id,
    ...data.attributes,
  };
  for (const [newCapability, templateFn] of Object.entries(capabilities)) {
    const type = typeOf(templateFn);
    assert(`expected value of ${newCapability} to be a function but found ${type}.`, type === 'function');
    data.relationships[newCapability] = {
      data: {
        type: 'capabilities',
        id: templateFn(context),
      },
    };
  }

  if (included) {
    return {
      data,
      included,
    };
  } else {
    return data;
  }
}
