/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { module, test } from 'qunit';
import { setupTest } from 'ember-qunit';
import { SUDO_PATHS, SUDO_PATH_PREFIXES } from 'vault/models/capabilities';

import { run } from '@ember/runloop';

module('Unit | Model | capabilities', function (hooks) {
  setupTest(hooks);

  test('it exists', function (assert) {
    const model = run(() => this.owner.lookup('service:store').createRecord('capabilities'));
    assert.ok(!!model);
  });

  test('it reads capabilities', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: 'foo',
        capabilities: ['list', 'read'],
      })
    );

    assert.ok(model.canRead);
    assert.ok(model.canList);
    assert.notOk(model.canUpdate);
    assert.notOk(model.canDelete);
  });

  test('it allows everything if root is present', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: 'foo',
        capabilities: ['root', 'deny', 'read'],
      })
    );
    assert.ok(model.canRead);
    assert.ok(model.canCreate);
    assert.ok(model.canUpdate);
    assert.ok(model.canDelete);
    assert.ok(model.canList);
  });

  test('it denies everything if deny is present', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: 'foo',
        capabilities: ['sudo', 'deny', 'read'],
      })
    );
    assert.notOk(model.canRead);
    assert.notOk(model.canCreate);
    assert.notOk(model.canUpdate);
    assert.notOk(model.canDelete);
    assert.notOk(model.canList);
  });

  test('it requires sudo on sudo paths', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: SUDO_PATHS[0],
        capabilities: ['sudo', 'read'],
      })
    );
    assert.ok(model.canRead);
    assert.notOk(model.canCreate, 'sudo requires the capability to be set as well');
    assert.notOk(model.canUpdate);
    assert.notOk(model.canDelete);
    assert.notOk(model.canList);
  });

  test('it requires sudo on sudo paths prefixes', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: SUDO_PATH_PREFIXES[0] + '/foo',
        capabilities: ['sudo', 'read'],
      })
    );
    assert.ok(model.canRead);
    assert.notOk(model.canCreate, 'sudo requires the capability to be set as well');
    assert.notOk(model.canUpdate);
    assert.notOk(model.canDelete);
    assert.notOk(model.canList);
  });

  test('it does not require sudo on sys/leases/revoke if update capability is present and path is not fully a sudo prefix', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: 'sys/leases/revoke',
        capabilities: ['update', 'read'],
      })
    );
    assert.ok(model.canRead);
    assert.notOk(model.canCreate, 'sudo requires the capability to be set as well');
    assert.ok(model.canUpdate, 'should not require sudo if it has update');
    assert.notOk(model.canDelete);
    assert.notOk(model.canList);
  });

  test('it requires sudo on prefix path even if capability is present', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: SUDO_PATH_PREFIXES[0] + '/aws',
        capabilities: ['update', 'read'],
      })
    );
    assert.notOk(model.canRead);
    assert.notOk(model.canCreate);
    assert.notOk(model.canUpdate, 'should still require sudo');
    assert.notOk(model.canDelete);
    assert.notOk(model.canList);
  });

  test('it does not require sudo on prefix path if both update and sudo capabilities are present', function (assert) {
    const model = run(() =>
      this.owner.lookup('service:store').createRecord('capabilities', {
        path: SUDO_PATH_PREFIXES[0] + '/aws',
        capabilities: ['sudo', 'update', 'read'],
      })
    );
    assert.ok(model.canRead);
    assert.notOk(model.canCreate);
    assert.ok(model.canUpdate, 'should not require sudo');
    assert.notOk(model.canDelete);
    assert.notOk(model.canList);
  });
});
