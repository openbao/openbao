/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import EditBase from './secret-edit';
import subkeyPaths from 'vault/utils/kv-v2-subkey-paths';

export default EditBase.extend({
  store: service(),

  queryParams: {
    version: {
      refreshModel: true,
    },
  },

  fetchV2VersionModel(_secretModel, version, targetVersion) {
    // The Secret page loads values only when the user requests them.
    return version || this.stubV2VersionModel(targetVersion);
  },

  async model(params) {
    const model = await this._super(...arguments);
    const { secret, capabilities } = model;
    if (!secret.engine?.isV2KV) {
      return model;
    }

    // PATCH always operates on the latest version. An explicit version is only
    // eligible when the metadata confirms it is current.
    const targetVersion = this.getTargetVersion(secret.currentVersion, params.version);
    const view = {
      canPatch: capabilities.canPatch && (!params.version || targetVersion === secret.currentVersion),
      canReadValues: capabilities.canRead || !capabilities.capabilities?.length,
    };
    model.subkeyView = view;
    if (secret.selectedVersion.deleted || secret.selectedVersion.destroyed) {
      return model;
    }

    try {
      const adapter = this.store.adapterFor('secret-v2-version');
      const { subkeys, metadata } = await adapter.readSubkeys(
        this.enginePathParam(),
        this.secretParam(),
        targetVersion
      );
      if (metadata && secret.failedServerRead) {
        secret.set(
          'selectedVersion',
          this.stubV2VersionModel(metadata.version, {
            createdTime: metadata.created_time,
            deletionTime: metadata.deletion_time,
            destroyed: metadata.destroyed,
          })
        );
      }
      view.paths = subkeys ? subkeyPaths(subkeys) : null;
    } catch (error) {
      if (error.httpStatus === 403) {
        view.readDenied = true;
      } else if (error.httpStatus !== 404) {
        view.readError = true;
      }
    }
    return model;
  },

  setupController(controller, model) {
    this._super(...arguments);
    controller.set('subkeyView', model.subkeyView);
  },
});
