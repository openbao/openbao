/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Service, { inject as service } from '@ember/service';
import { task } from 'ember-concurrency';
import { tracked } from '@glimmer/tracking';

export default class VersionService extends Service {
  @service store;
  @tracked version = null;

  get hasControlGroups() {
    return false;
  }

  @task
  *getVersion() {
    if (this.version) return;
    const response = yield this.store.adapterFor('cluster').health();
    this.version = response.version;
    return;
  }

  fetchVersion() {
    return this.getVersion.perform();
  }
}
