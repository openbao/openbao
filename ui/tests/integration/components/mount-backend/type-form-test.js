/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { module, test } from 'qunit';
import { setupRenderingTest } from 'vault/tests/helpers';
import { click, render } from '@ember/test-helpers';
import { hbs } from 'ember-cli-htmlbars';
import sinon from 'sinon';
import { allEngines, mountableEngines } from 'vault/helpers/mountable-secret-engines';
import { methods } from 'vault/helpers/mountable-auth-methods';

const secretTypes = mountableEngines().map((engine) => engine.type);
allEngines().map((engine) => engine.type);
const authTypes = methods().map((auth) => auth.type);

module('Integration | Component | mount-backend/type-form', function (hooks) {
  setupRenderingTest(hooks);

  hooks.beforeEach(function () {
    this.setType = sinon.spy();
  });

  test('it calls secrets setMountType only on next click', async function (assert) {
    const spy = sinon.spy();
    this.set('setType', spy);
    await render(hbs`<MountBackend::TypeForm @mountType="secret" @setMountType={{this.setType}} />`);

    assert
      .dom('[data-test-mount-type]')
      .exists({ count: secretTypes.length }, 'Renders all mountable engines');
    await click(`[data-test-mount-type="pki"]`);
    assert.dom(`[data-test-mount-type="pki"] input`).isChecked(`pki is checked`);
    assert.ok(spy.notCalled, 'callback not called');
    await click(`[data-test-mount-type="ssh"]`);
    assert.dom(`[data-test-mount-type="ssh"] input`).isChecked(`ssh is checked`);
    assert.ok(spy.notCalled, 'callback not called');
    await click('[data-test-mount-next]');
    assert.ok(spy.calledOnceWith('ssh'));
  });

  test('it calls auth setMountType only on next click', async function (assert) {
    const spy = sinon.spy();
    this.set('setType', spy);
    await render(hbs`<MountBackend::TypeForm @setMountType={{this.setType}} />`);

    assert
      .dom('[data-test-mount-type]')
      .exists({ count: authTypes.length }, 'Renders all mountable auth methods');
    await click(`[data-test-mount-type="ldap"]`);
    assert.dom(`[data-test-mount-type="ldap"] input`).isChecked(`ldap is checked`);
    assert.ok(spy.notCalled, 'callback not called');
    await click(`[data-test-mount-type="kubernetes"]`);
    assert.dom(`[data-test-mount-type="kubernetes"] input`).isChecked(`kubernetes is checked`);
    assert.ok(spy.notCalled, 'callback not called');
    await click('[data-test-mount-next]');
    // assert.ok(spy.calledOnceWith('jwt'));
  });
});
