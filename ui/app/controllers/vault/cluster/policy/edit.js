/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { action } from '@ember/object';
import { inject as service } from '@ember/service';
import transitionToSafe from 'vault/utils/transition-to-safe';

export default class PolicyEditController extends Controller {
  @service router;
  @service flashMessages;

  @action
  async deletePolicy() {
    const { policyType, name } = this.model;
    try {
      await this.model.destroyRecord();
      this.flashMessages.success(`${policyType.toUpperCase()} policy "${name}" was successfully deleted.`);
      transitionToSafe(this.router, 'vault.cluster.policies', policyType);
    } catch (error) {
      this.model.rollbackAttributes();
      const errors = error.errors ? error.errors.join('. ') : error.message;
      const message = `There was an error deleting the ${policyType.toUpperCase()} policy "${name}": ${errors}.`;
      this.flashMessages.danger(message);
    }
  }
}
