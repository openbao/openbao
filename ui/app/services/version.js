/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Service, { inject as service } from '@ember/service';
import { keepLatestTask, task } from 'ember-concurrency';
import { tracked } from '@glimmer/tracking';

export default class VersionService extends Service {
  @service store;
  @tracked features = [];
  @tracked version = null;

  get hasNamespaces() {
    return this.features.includes('Namespaces');
  }

  get hasControlGroups() {
    return this.features.includes('Control Groups');
  }

  get isEnterprise() {
    if (!this.version) return false;
    return this.version.includes('+');
  }

  get isOSS() {
    return !this.isEnterprise;
  }

  @task
  *getVersion() {
    if (this.version) return;
    const response = yield this.store.adapterFor('cluster').health();
    this.version = response.version;
    return;
  }

  @keepLatestTask
  *getFeatures() {
    if (this.features?.length || this.isOSS) {
      return;
    }
    try {
      const response = yield this.store.adapterFor('cluster').features();
      this.features = response.features;
      return;
    } catch {
      // if we fail here, we're likely in DR Secondary mode and don't need to worry about it
    }
  }

  fetchVersion() {
    return this.getVersion.perform();
  }

  fetchFeatures() {
    return this.getFeatures.perform();
  }
}
