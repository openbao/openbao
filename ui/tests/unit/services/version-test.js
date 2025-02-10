/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { module, test } from 'qunit';
import { setupTest } from 'ember-qunit';

module('Unit | Service | version', function (hooks) {
  setupTest(hooks);

  test('setting version computes isOSS properly', function (assert) {
    const service = this.owner.lookup('service:version');
    service.version = '0.9.5';
    assert.true(service.isOSS);
    assert.false(service.isEnterprise);
  });
});
