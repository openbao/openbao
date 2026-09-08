/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { inject as service } from '@ember/service';
import transitionToSafe from 'vault/utils/transition-to-safe';

export default class MfaLoginEnforcementIndexController extends Controller {
  @service router;
  @service flashMessages;

  queryParams = ['tab'];
  tab = 'targets';

  @tracked showDeleteConfirmation = false;
  @tracked deleteError;

  @action
  async delete() {
    try {
      await this.model.destroyRecord();
      this.showDeleteConfirmation = false;
      this.flashMessages.success('MFA login enforcement deleted successfully');
      transitionToSafe(this.router, 'vault.cluster.access.mfa.enforcements');
    } catch (error) {
      this.deleteError = error;
    }
  }
}
