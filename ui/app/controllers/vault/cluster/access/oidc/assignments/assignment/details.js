/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { action } from '@ember/object';
import { inject as service } from '@ember/service';
import transitionToSafe from 'vault/utils/transition-to-safe';

export default class OidcAssignmentDetailsController extends Controller {
  @service router;
  @service flashMessages;

  @action
  async delete() {
    try {
      await this.model.destroyRecord();
      this.flashMessages.success('Assignment deleted successfully');
      transitionToSafe(this.router, 'vault.cluster.access.oidc.assignments');
    } catch (error) {
      this.model.rollbackAttributes();
      const message = error.errors ? error.errors.join('. ') : error.message;
      this.flashMessages.danger(message);
    }
  }
}
