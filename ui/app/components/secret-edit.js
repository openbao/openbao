/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/* eslint ember/no-computed-properties-in-native-classes: 'warn' */
/**
 * @module SecretEdit
 * SecretEdit component manages the secret and model data, and displays either the create, update, empty state or show view of a KV secret.
 *
 * @example
 * ```js
 * <SecretEdit @model={{model}} @mode="create" @baseKey={{this.baseKey}} @key={{this.model}} @initialKey={{this.initialKey}} @onRefresh={{action "refresh"}} @onToggleAdvancedEdit={{action "toggleAdvancedEdit"}} @preferAdvancedEdit={{this.preferAdvancedEdit}}/>
 * ```
/This component is initialized from the secret-edit-layout.hbs file
 * @param {object} model - Model returned from secret-v2 which is generated in the secret-edit route
 * @param {string} mode - Edit, create, etc.
 * @param {string} baseKey - Provided for navigation.
 * @param {object} key - Passed through, copy of the model.
 * @param {string} initialKey - model's name.
 * @param {function} onRefresh - action that refreshes the model
 * @param {function} onToggleAdvancedEdit - changes the preferAdvancedEdit to true or false
 * @param {boolean} preferAdvancedEdit - property set from the controller of show/edit/create route passed in through secret-edit-layout
 */

import { inject as service } from '@ember/service';
import Component from '@glimmer/component';
import { action } from '@ember/object';
import { cached, tracked } from '@glimmer/tracking';
import keyUtils from 'vault/lib/key-utils';
import KVObject from 'vault/lib/kv-object';
import { maybeQueryRecord } from 'vault/macros/maybe-query-record';

export default class SecretEdit extends Component {
  @service store;

  @tracked secretData = null;
  @tracked isV2 = false;
  @tracked codemirrorString = null;
  @tracked valueRead;
  @tracked jsonView;

  // fired on did-insert from render modifier
  @action
  createKvData(elem, [model]) {
    // the model may not have resolved yet when the component inserts
    if (!model) {
      return;
    }
    this.isV2 = Boolean(model.selectedVersion);
    if (this.isV2 && !this.args.subkeyView && !model.secretData) {
      model.secretData = model.belongsTo('selectedVersion').value().secretData;
    }
    this.secretData = KVObject.create({ content: [] }).fromJSON(
      this.args.subkeyView ? null : model.secretData
    );
    this.codemirrorString = this.secretData.toJSONString();
  }

  @maybeQueryRecord(
    'capabilities',
    (context) => {
      if (!context.args.model || context.args.mode === 'create') {
        return;
      }
      const backend = context.isV2 ? context.args.model.engine.id : context.args.model.backend;
      const id = context.args.model.id;
      const path = context.isV2 ? `${backend}/data/${id}` : `${backend}/${id}`;
      return {
        id: path,
      };
    },
    'isV2',
    'model',
    'model.id',
    'mode'
  )
  checkSecretCapabilities;

  get canUpdateSecretData() {
    return this.checkSecretCapabilities.get('canUpdate');
  }

  get canReadSecretData() {
    return this.checkSecretCapabilities.get('canRead');
  }

  @maybeQueryRecord(
    'capabilities',
    (context) => {
      if (!context.args.model || !context.isV2) {
        return;
      }
      const backend = context.args.model.backend;
      const id = context.args.model.id;
      const path = `${backend}/metadata/${id}`;
      return {
        id: path,
      };
    },
    'isV2',
    'model',
    'model.id',
    'mode'
  )
  checkMetadataCapabilities;

  get canDeleteSecretMetadata() {
    return this.checkMetadataCapabilities.get('canDelete');
  }

  get canUpdateSecretMetadata() {
    return this.checkMetadataCapabilities.get('canUpdate');
  }

  get canReadSecretMetadata() {
    return this.checkMetadataCapabilities.get('canRead');
  }

  get requestInFlight() {
    return this.model?.isLoading || this.model?.isReloading || this.model?.isSaving;
  }

  get buttonDisabled() {
    return this.requestInFlight || this.model?.isFolder || this.model?.flagIsInvalid;
  }

  get modelForData() {
    const { model } = this.args;
    if (!model) return null;
    return this.isV2 ? model.belongsTo('selectedVersion').value() : model;
  }

  get basicModeDisabled() {
    return this.secretDataIsAdvanced || this.showAdvancedMode === false;
  }

  get secretDataAsJSON() {
    return this.secretData.toJSON();
  }

  get secretDataIsAdvanced() {
    return !this.args.subkeyView && this.secretData.isAdvanced();
  }

  get showAdvancedMode() {
    if (this.args.subkeyView) {
      return !this.valuesHidden && this.jsonView === this.args.subkeyView;
    }
    return this.secretDataIsAdvanced || this.args.preferAdvancedEdit;
  }

  get isWriteWithoutRead() {
    if (this.args.subkeyView) {
      return !this.args.subkeyView.canReadValues || this.currentValueRead?.httpStatus === 403;
    }
    if (!this.args.model) {
      return false;
    }
    // if the version couldn't be read from the server
    if (this.isV2 && this.modelForData.failedServerRead) {
      return true;
    }
    // if the model couldn't be read from the server
    if (!this.isV2 && this.args.model.failedServerRead) {
      return true;
    }
    return false;
  }

  get currentValueRead() {
    return this.valueRead?.view === this.args.subkeyView ? this.valueRead : null;
  }

  get valuesHidden() {
    return this.args.subkeyView && this.currentValueRead?.status !== 'loaded';
  }

  get canShowValues() {
    return (
      this.valuesHidden &&
      !this.args.subkeyView.paths?.length &&
      !this.isWriteWithoutRead &&
      !this.modelForData.deleted &&
      !this.modelForData.destroyed
    );
  }

  @cached
  get subkeyData() {
    const { subkeyView } = this.args;
    if (!subkeyView || this.modelForData.deleted || this.modelForData.destroyed) {
      return null;
    }
    const paths =
      subkeyView.paths ?? (!this.valuesHidden && keyUtils.subkeyPaths(this.modelForData.secretData));
    return paths
      ? {
          view: subkeyView,
          paths,
          patchVersion: subkeyView.canPatch ? this.modelForData.version : null,
        }
      : null;
  }

  @action
  async showValues() {
    if (!this.canShowValues) {
      return;
    }
    try {
      await this.loadValues();
    } catch {
      // The page displays errors from the full-secret action.
    }
  }

  @action
  async loadValues() {
    const currentRead = this.currentValueRead;
    if (currentRead?.status === 'loaded') {
      return;
    }
    if (currentRead?.status === 'loading') {
      return currentRead.promise;
    }
    const view = this.args.subkeyView;
    const request = { view, status: 'loading', promise: this.modelForData.reload() };
    this.valueRead = request;
    let result;
    try {
      await request.promise;
      result = { view, status: 'loaded' };
    } catch (error) {
      result = { view, status: 'failed', httpStatus: error.httpStatus };
      throw error;
    } finally {
      if (!this.isDestroying && this.args.subkeyView === view && this.valueRead === request) {
        this.valueRead = result;
      }
    }
  }

  @action
  refresh() {
    this.args.onRefresh();
  }

  @action
  toggleAdvanced(bool) {
    if (this.args.subkeyView) {
      this.jsonView = bool ? this.args.subkeyView : null;
    } else {
      this.args.onToggleAdvancedEdit(bool);
    }
  }
}
