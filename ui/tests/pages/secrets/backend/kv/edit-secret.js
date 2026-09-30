/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { Base } from '../create';
import { isPresent, clickable, visitable, create, fillable, collection } from 'ember-cli-page-object';

export default create({
  ...Base,
  path: fillable('[data-test-secret-path="true"]'),

  createRows: collection('.info-table-row', {
    secretKey: fillable('[data-test-secret-key]'),
    secretValue: fillable('[data-test-secret-value] textarea'),
  }),

  editRows: collection('.columns.has-no-shadow', {
    secretKey: fillable('[data-test-secret-key]'),
    secretValue: fillable('[data-test-secret-value] textarea'),
  }),

  secretKey: async function (value) {
    if (this.createRows.length > 0) {
      return this.createRows[0].secretKey(value);
    }
    return this.editRows[0].secretKey(value);
  },

  secretValue: async function (value) {
    if (this.createRows.length > 0) {
      return this.createRows[0].secretValue(value);
    }
    return this.editRows[0].secretValue(value);
  },

  save: clickable('[data-test-secret-save]'),
  deleteBtn: clickable('[data-test-secret-delete] button'),
  confirmBtn: clickable('[data-test-confirm-button]'),
  visitEdit: visitable('/vault/secrets/:backend/edit/:id'),
  visitEditRoot: visitable('/vault/secrets/:backend/edit'),
  toggleJSON: clickable('[data-test-toggle-input="json"]'),
  toggleMetadata: clickable('[data-test-show-metadata-toggle]'),
  metadataTab: clickable('[data-test-secret-metadata-tab]'),
  hasMetadataFields: isPresent('[data-test-metadata-fields]'),
  maxVersion: fillable('[data-test-input="maxVersions"]'),
  startCreateSecret: clickable('[data-test-secret-create]'),

  deleteSecret() {
    return this.deleteBtn().confirmBtn();
  },

  createSecret: async function (path, key, value) {
    await this.path(path);
    await this.createRows[0].secretKey(key);
    await this.createRows[0].secretValue(value);
    return this.save();
  },

  createSecretDontSave: async function (path, key, value) {
    await this.path(path);
    await this.createRows[0].secretKey(key);
    return this.createRows[0].secretValue(value);
  },

  createSecretWithMetadata: async function (path, key, value, maxVersion) {
    await this.path(path);
    await this.createRows[0].secretKey(key);
    await this.createRows[0].secretValue(value);
    await this.toggleMetadata();
    await this.maxVersion(maxVersion);
    return this.save();
  },

  editSecret: async function (key, value) {
    await this.editRows[0].secretKey(key);
    await this.editRows[0].secretValue(value);
    return this.save();
  },
});
