/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { Base } from '../create';
import { isPresent, clickable, visitable, create, fillable, collection } from 'ember-cli-page-object';

export default create({
  ...Base,
  path: fillable('[data-test-secret-path="true"]'),
  secretRows: collection('[data-test-secret-row]', {
    key: fillable('[data-test-secret-key]'),
    value: fillable('[data-test-secret-value] textarea'),
  }),
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
    this.path(path);
    this.secretRows.objectAt(0).key(key);
    this.secretRows.objectAt(0).value(value);
    return this.save();
  },
  createSecretDontSave: async function (path, key, value) {
    this.path(path);
    this.secretRows.objectAt(0).key(key);
    this.secretRows.objectAt(0).value(value);
    return;
  },
  createSecretWithMetadata: async function (path, key, value, maxVersion) {
    this.path(path);
    this.secretRows.objectAt(0).key(key);
    this.secretRows.objectAt(0).value(value);
    return this.toggleMetadata().maxVersion(maxVersion).save();
  },
  editSecret: async function (key, value) {
    this.secretRows.objectAt(0).key(key);
    this.secretRows.objectAt(0).value(value);
    return this.save();
  },
});
