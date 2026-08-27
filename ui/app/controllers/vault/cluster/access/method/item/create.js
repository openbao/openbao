/**
 * Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { inject as service } from '@ember/service';
import removeRecord from 'vault/utils/remove-record';

export default Controller.extend({
  store: service(),

  cleanupModel() {
    const model = this.model;

    if (!model) {
      return;
    }

    if (model.isSaving || model.isDestroyed || model.isDestroying) {
      return;
    }

    // Rollback any dirty attributes before unloading to avoid memory leaks
    if (model.hasDirtyAttributes && typeof model.rollbackAttributes === 'function') {
      model.rollbackAttributes();
    }

    // controllers are singletons — always unset
    this.model = null;

    if (typeof model.unloadRecord === 'function') {
      removeRecord(this.store, model);
    }
  },
});
