/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/* eslint ember/no-computed-properties-in-native-classes: 'warn' */
import Ember from 'ember';
import { inject as service } from '@ember/service';
import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { task } from 'ember-concurrency';

const getErrorMessage = (errors) => {
  const errorMessage =
    errors?.join('. ') || 'Something went wrong. Check the OpenBao logs for more information.';
  return errorMessage;
};
export default class SecretDeleteMenu extends Component {
  @service store;
  @service router;
  @service flashMessages;

  @tracked showDeleteModal = false;
  @tracked undeleteVersionPath = null;
  @tracked destroyVersionPath = null;
  @tracked v2UpdatePath = null;
  @tracked secretDataPath = null;
  @tracked secretSoftDataPath = null;

  constructor() {
    super(...arguments);
    this.loadCapabilities.perform();
  }

  @task
  *loadCapabilities() {
    try {
      // Load undelete capability
      if (this.args.modelForData?.id) {
        const [backend, id] = JSON.parse(this.args.modelForData.id);
        const undelData = yield this.store.queryRecord('capabilities', {
          id: `${backend}/undelete/${id}`,
        });
        this.undeleteVersionPath = undelData;
      }

      // Load destroy capability
      if (this.args.modelForData?.id) {
        const [backend, id] = JSON.parse(this.args.modelForData.id);
        const destroyData = yield this.store.queryRecord('capabilities', {
          id: `${backend}/destroy/${id}`,
        });
        this.destroyVersionPath = destroyData;
      }

      // Load v2 update capability
      if (this.args.model?.engine && this.args.model?.id) {
        const backend = this.args.model.engine.id;
        const id = this.args.model.id;
        const v2Data = yield this.store.queryRecord('capabilities', {
          id: `${backend}/metadata/${id}`,
        });
        this.v2UpdatePath = v2Data;
      }

      // Load secret data capability
      if (this.args.model?.id && this.args.mode !== 'create') {
        const backend = this.args.isV2 ? this.args.model.engine.id : this.args.model.backend;
        const id = this.args.model.id;
        const path = this.args.isV2 ? `${backend}/data/${id}` : `${backend}/${id}`;
        const secretData = yield this.store.queryRecord('capabilities', { id: path });
        this.secretDataPath = secretData;
      }

      // Load secret soft data capability
      if (this.args.model?.id && this.args.mode !== 'create') {
        const backend = this.args.isV2 ? this.args.model.engine.id : this.args.model.backend;
        const id = this.args.model.id;
        const path = this.args.isV2 ? `${backend}/delete/${id}` : `${backend}/${id}`;
        const secretSoftData = yield this.store.queryRecord('capabilities', { id: path });
        this.secretSoftDataPath = secretSoftData;
      }
    } catch (error) {
      // Swallow capability check errors
      console.error('Failed to load capabilities:', error);
    }
  }

  get canUndeleteVersion() {
    return this.undeleteVersionPath?.canUpdate ?? false;
  }

  get canDestroyVersion() {
    return this.destroyVersionPath?.canUpdate ?? false;
  }

  get canDestroyAllVersions() {
    return this.v2UpdatePath?.canDelete ?? false;
  }

  get canDeleteSecretData() {
    return this.secretDataPath?.canDelete ?? false;
  }

  get canSoftDeleteSecretData() {
    return this.secretSoftDataPath?.canUpdate ?? false;
  }

  get isLatestVersion() {
    // must have metadata access.
    const { model } = this.args;
    if (!model) return false;
    const latestVersion = model.currentVersion;
    const selectedVersion = model.selectedVersion.version;
    if (latestVersion !== selectedVersion) {
      return false;
    }
    return true;
  }

  @action
  handleDelete(deleteType) {
    // deleteType should be 'delete', 'destroy', 'undelete', 'delete-latest-version', 'destroy-all-versions', 'v1'
    if (!deleteType) {
      return;
    }
    if (deleteType === 'destroy-all-versions' || deleteType === 'v1') {
      this.args.model.destroyRecord().then(() => {
        return this.router.transitionTo('vault.cluster.secrets.backend.list-root');
      });
    } else {
      // if they do not have read access on the metadata endpoint we need to pull the version from modelForData so they can perform delete and undelete operations
      // only perform if no access to metadata otherwise it will only delete latest version for any deleteType === delete
      let currentVersionForNoReadMetadata;
      if (!this.args.canReadSecretMetadata) {
        currentVersionForNoReadMetadata = this.args.modelForData?.version;
      }
      return this.store
        .adapterFor('secret-v2-version')
        .v2DeleteOperation(this.store, this.args.modelForData.id, deleteType, currentVersionForNoReadMetadata)
        .then((resp) => {
          if (Ember.testing) {
            this.showDeleteModal = false;
            // we don't want a refresh otherwise test loop will rerun in a loop
            return;
          }
          if (!resp) {
            this.showDeleteModal = false;
            this.args.refresh();
            return;
          }
          if (resp.isAdapterError) {
            const errorMessage = getErrorMessage(resp.errors);
            this.flashMessages.danger(errorMessage);
          } else {
            // not likely to ever get to this situation, but adding just in case.
            location.reload();
          }
        });
    }
  }
}
