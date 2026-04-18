/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import Controller from '@ember/controller';

export default class InitController extends Controller {
  @tracked
  keyData;
  @tracked
  secret_shares;
  @tracked
  secret_threshold;
  @tracked
  pgp_keys;
  @tracked
  use_pgp;
  @tracked
  loading;
  @tracked prefersInit = false;

  constructor() {
    super();
    this.reset();
  }

  reset() {
    this.keyData = null;
    this.secret_shares = null;
    this.secret_threshold = null;
    this.pgp_key = null;
    this.use_pgp = false;
    this.loading = false;
  }

  initSuccess(resp) {
    this.loading = false;
    this.keyData = resp;
    this.model.reload();
  }

  initError(e) {
    this.loading = false;
    if (e.httpStatus === 400) {
      this.errors = e.errors;
    } else {
      throw e;
    }
  }

  get keyFilename() {
    return `vault-cluster-${this.model.name}`;
  }

  @action
  initCluster(event) {
    event.preventDefault();
    const data = {};
    const isCloudSeal = !!this.model.sealType && this.model.sealType !== 'shamir';
    if (this.secret_shares) {
      const shares = parseInt(this.secret_shares, 10);
      if (isCloudSeal) {
        data.recovery_shares = shares;
        // API will throw an error if secret_shares is passed for seal types other than shamir (transit, AWSKMS etc.)
      } else {
        data.secret_shares = shares;
      }
    }
    if (this.secret_threshold) {
      const threshold = parseInt(this.secret_threshold, 10);
      if (isCloudSeal) {
        data.recovery_threshold = threshold;
        // API will throw an error if secret_threshold is passed for seal types other than shamir (transit, AWSKMS etc.)
      } else {
        data.secret_threshold = threshold;
      }
    }
    if (this.use_pgp) {
      data.pgp_keys = this.pgp_keys;
    }
    if (this.use_pgp && isCloudSeal) {
      data.recovery_pgp_keys = this.pgp_keys;
    }
    if (this.use_pgp_for_root) {
      data.root_token_pgp_key = this.root_token_pgp_key;
    }

    const store = this.model.store;
    this.loading = true;
    this.errors = null;
    store
      .adapterFor('cluster')
      .initCluster(data)
      .then(
        (resp) => this.initSuccess(resp),
        (...errArgs) => this.initError(...errArgs)
      );
  }

  @action
  setKeys(data) {
    this.pgp_keys = data;
  }

  @action
  setRootKey([key]) {
    this.root_token_pgp_key = key;
  }

  @action
  setPrefersInit() {
    this.prefersInit = true;
  }
}
