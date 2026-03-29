/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { attr } from '@ember-data/model';
import { match } from '@ember/object/computed';
import utils from 'vault/lib/key-utils';
import { computed } from '@ember/object';

/* sample response
{
  "id": "auth/token/create/25c75065466dfc5f920525feafe47502c4c9915c",
  "issue_time": "2017-04-30T10:18:11.228946471-04:00",
  "expire_time": "2017-04-30T11:18:11.228946708-04:00",
  "last_renewal": null,
  "renewable": true,
  "ttl": 3558
}

*/

export default Model.extend({
  issueTime: attr('string'),
  expireTime: attr('string'),
  lastRenewal: attr('string'),
  renewable: attr('boolean'),
  ttl: attr('number'),
  isAuthLease: match('id', /^auth/),

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
});
