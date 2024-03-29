/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import EmberObject, { computed } from '@ember/object';
import Evented from '@ember/object/evented';

export const fakeWindow = EmberObject.extend(Evented, {
  init() {
    this._super(...arguments);
    this.on('close', () => {
      this.set('closed', true);
    });
  },
  screen: computed(function () {
    return {
      height: 600,
      width: 500,
    };
  }),
  origin: 'https://my-openbao.com',
  closed: false,
  open() {},
  close() {},
});

export const buildMessage = (opts) => ({
  isTrusted: true,
  origin: 'https://my-openbao.com',
  data: {
    source: 'oidc-callback',
    path: 'foo',
    state: 'state',
    code: 'code',
  },
  ...opts,
});
