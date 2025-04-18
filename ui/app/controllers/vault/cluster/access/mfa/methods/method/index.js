/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Controller from '@ember/controller';
import { inject as service } from '@ember/service';
import { action } from '@ember/object';

export default class MfaMethodController extends Controller {
  @service router;
  @service flashMessages;

  queryParams = ['tab'];
  tab = 'config';

  @action
  async deleteMethod() {
    try {
      await this.model.method.destroyRecord();
      this.flashMessages.success('MFA method deleted successfully.');
      this.router.transitionTo('vault.cluster.access.mfa.methods');
    } catch {
      this.flashMessages.danger(`There was an error deleting this MFA method.`);
    }
  }
}
