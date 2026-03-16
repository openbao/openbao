/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { belongsTo, hasMany, attr } from '@ember-data/model';
import { computed } from '@ember/object'; // eslint-disable-line
import { alias } from '@ember/object/computed'; // eslint-disable-line
import { expandAttributeMeta } from 'vault/utils/field-to-attrs';
import utils from 'vault/lib/key-utils';
import lazyCapabilities, { apiPath } from 'vault/macros/lazy-capabilities';
import { withModelValidations } from 'vault/decorators/model-validations';

const validations = {
  maxVersions: [
    { type: 'number', message: 'Maximum versions must be a number.' },
    { type: 'length', options: { min: 1, max: 16 }, message: 'You cannot go over 16 characters.' },
  ],
};

@withModelValidations(validations)
class SecretV2Model extends Model {}
export default SecretV2Model.extend({
  failedServerRead: attr('boolean'),
  engine: belongsTo('secret-engine', { async: false }),
  engineId: attr('string'),
  versions: hasMany('secret-v2-version', { async: false, inverse: null }),
  selectedVersion: belongsTo('secret-v2-version', { async: false, inverse: 'secret' }),
  createdTime: attr(),
  updatedTime: attr(),
  currentVersion: attr('number'),
  oldestVersion: attr('number'),
  customMetadata: attr('object', {
    editType: 'kv',
    subText: 'An optional set of informational key-value pairs that will be stored with all secret versions.',
  }),
  maxVersions: attr('number', {
    defaultValue: 0,
    label: 'Maximum number of versions',
    subText:
      'The number of versions to keep per key. Once the number of keys exceeds the maximum number set here, the oldest version will be permanently deleted.',
  }),
  casRequired: attr('boolean', {
    defaultValue: false,
    label: 'Require Check and Set',
    subText:
      'Writes will only be allowed if the key’s current version matches the version specified in the cas parameter.',
  }),
  deleteVersionAfter: attr({
    defaultValue: 0,
    editType: 'ttl',
    label: 'Automate secret deletion',
    helperTextDisabled: 'A secret’s version must be manually deleted.',
    helperTextEnabled: 'Delete all new versions of this secret after',
  }),
  fields: computed(function () {
    return expandAttributeMeta(this, ['customMetadata', 'maxVersions', 'casRequired', 'deleteVersionAfter']);
  }),
  secretDataPath: lazyCapabilities(apiPath`${'engineId'}/data/${'id'}`, 'engineId', 'id'),
  secretMetadataPath: lazyCapabilities(apiPath`${'engineId'}/metadata/${'id'}`, 'engineId', 'id'),

  canListMetadata: alias('secretMetadataPath.canList'),
  canReadMetadata: alias('secretMetadataPath.canRead'),
  canUpdateMetadata: alias('secretMetadataPath.canUpdate'),

  canReadSecretData: alias('secretDataPath.canRead'),
  canEditSecretData: alias('secretDataPath.canUpdate'),
  canDeleteSecretData: alias('secretDataPath.canDelete'),

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
