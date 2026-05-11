/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { attr } from '@ember-data/model';
import { computed } from '@ember/object';
import { alias } from '@ember/object/computed';
import utils from 'vault/lib/key-utils';
import lazyCapabilities, { apiPath } from 'vault/macros/lazy-capabilities';

export default Model.extend({
  failedServerRead: attr('boolean'),
  auth: attr('string'),
  lease_duration: attr('number'),
  lease_id: attr('string'),
  renewable: attr('boolean'),
  // what attribute has the path for the key
  // will.be 'path' for v2 or 'id' v1
  pathAttr: 'path',
  flags: null,

  initialParentKey: null,

  isCreating: computed('initialParentKey', function () {
    return this.initialParentKey != null;
  }),

  pathVal() {
    return this[this.pathAttr] || this.id;
  },

  // rather than using defineProperty for all of these,
  // we're just going to hardcode the known keys for the path ('id' and 'path')
  isFolder: computed('id', 'path', function () {
    return utils.keyIsFolder(this.pathVal());
  }),

  keyParts: computed('id', 'path', function () {
    return utils.keyPartsForKey(this.pathVal());
  }),

  parentKey: computed('id', 'path', 'isCreating', {
    get: function () {
      return this.isCreating ? this.initialParentKey : utils.parentKeyForKey(this.pathVal());
    },
    set: function (_, value) {
      return value;
    },
  }),

  keyWithoutParent: computed('id', 'path', 'parentKey', {
    get: function () {
      var key = this.pathVal();
      return key ? key.replace(this.parentKey, '') : null;
    },
    set: function (_, value) {
      if (value && value.trim()) {
        this.set(this.pathAttr, this.parentKey + value);
      } else {
        this.set(this.pathAttr, null);
      }
      return value;
    },
  }),

  secretData: attr('object'),
  secretKeyAndValue: computed('secretData', function () {
    const data = this.secretData;
    return Object.keys(data).map((key) => {
      return { key, value: data[key] };
    });
  }),

  dataAsJSONString: computed('secretData', function () {
    return JSON.stringify(this.secretData, null, 2);
  }),

  isAdvancedFormat: computed('secretData', function () {
    const data = this.secretData;
    return data && Object.keys(data).some((key) => typeof data[key] !== 'string');
  }),

  helpText: attr('string'),
  // TODO this needs to be a relationship like `engine` on kv-v2
  backend: attr('string'),
  secretPath: lazyCapabilities(apiPath`${'backend'}/${'id'}`, 'backend', 'id'),
  canEdit: alias('secretPath.canUpdate'),
  canDelete: alias('secretPath.canDelete'),
  canRead: alias('secretPath.canRead'),
});
