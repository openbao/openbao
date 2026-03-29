/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import { alias } from '@ember/object/computed';
import Controller, { inject as controller } from '@ember/controller';
import { task, timeout } from 'ember-concurrency';

export default Controller.extend({
  flashMessages: service(),
  vaultController: controller('vault'),
  clusterController: controller('vault.cluster'),
  namespaceService: service('namespace'),
  auth: service(),
  router: service(),
  queryParams: [{ authMethod: 'with', oidcProvider: 'o' }],
  namespaceQueryParam: alias('clusterController.namespaceQueryParam'),
  wrappedToken: alias('vaultController.wrappedToken'),
  redirectTo: alias('vaultController.redirectTo'),
  authMethod: '',
  oidcProvider: '',

  updateNamespace: task(function* (value) {
    // debounce
    yield timeout(500);
    this.namespaceService.setNamespace(value, true);
    this.set('namespaceQueryParam', value);
  }).restartable(),

  authSuccess({ isRoot, namespace }) {
    let transition;
    if (this.redirectTo) {
      // here we don't need the namespace because it will be encoded in redirectTo
      transition = this.router.transitionTo(this.redirectTo);
      // reset the value on the controller because it's bound here
      this.set('redirectTo', '');
    } else {
      transition = this.router.transitionTo('vault.cluster', { queryParams: { namespace } });
    }
    transition.followRedirects().then(() => {
      if (isRoot) {
        this.flashMessages.warning(
          'You have logged in with a root token. As a security precaution, this root token will not be stored by your browser and you will need to re-authenticate after the window is closed or refreshed.'
        );
      }
    });
  },

  actions: {
    onAuthResponse(authResponse, backend, data) {
      const { mfa_requirement } = authResponse;
      // if an mfa requirement exists further action is required
      if (mfa_requirement) {
        this.set('mfaAuthData', { mfa_requirement, backend, data });
      } else {
        this.authSuccess(authResponse);
      }
    },
    onMfaSuccess(authResponse) {
      this.authSuccess(authResponse);
    },
    onMfaErrorDismiss() {
      this.setProperties({
        mfaAuthData: null,
        mfaErrors: null,
      });
    },
    cancelAuthentication() {
      this.set('cancelAuth', true);
      this.set('waitingForOktaNumberChallenge', false);
    },
  },
});
