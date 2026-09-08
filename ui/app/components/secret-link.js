/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@glimmer/component';
import { action } from '@ember/object';
import { service } from '@ember/service';
import { encodePath } from 'vault/utils/path-encoding-helpers';

export default class SecretLink extends Component {
  @service secretMountPath;

  get link() {
    const { mode, secret } = this.args;
    const route = `vault.cluster.secrets.backend.${mode}`;
    const backend = this.args.backend || this.secretMountPath.currentPath;
    if ((mode !== 'versions' && !secret) || secret === ' ') {
      const models = backend ? [backend] : [];
      return { route: `${route}-root`, models };
    } else {
      const models = backend ? [backend, encodePath(secret)] : [encodePath(secret)];
      return { route, models };
    }
  }
  get query() {
    const qp = this.args.queryParams || {};
    return qp.isQueryParams ? qp.values : qp;
  }

  @action
  onLinkClick() {
    if (this.args.onLinkClick) {
      this.args.onLinkClick(...arguments);
    }
  }
}
