/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/* eslint qunit/no-conditional-assertions: "warn" */
import { module, test } from 'qunit';
import { setupApplicationTest } from 'ember-qunit';
import sinon from 'sinon';
import { click, currentURL, visit, waitUntil, find } from '@ember/test-helpers';
import { supportedAuthBackends } from 'vault/helpers/supported-auth-backends';
import authForm from '../pages/components/auth-form';
import jwtForm from '../pages/components/auth-jwt';
import { create } from 'ember-cli-page-object';
import apiStub from 'vault/tests/helpers/noop-all-api-requests';
import logout from 'vault/tests/pages/logout';

const component = create(authForm);
const jwtComponent = create(jwtForm);

module('Acceptance | auth', function (hooks) {
  setupApplicationTest(hooks);

  hooks.beforeEach(function () {
    this.clock = sinon.useFakeTimers({
      now: Date.now(),
      shouldAdvanceTime: true,
    });
    this.server = apiStub({ usePassthrough: true });
    return logout.visit();
  });

  hooks.afterEach(function () {
    this.clock.restore();
    this.server.shutdown();
    return logout.visit();
  });

  test('auth query params', async function (assert) {
    const backends = supportedAuthBackends();
    assert.expect(backends.length + 1);
    await visit('/vault/auth');
    assert.strictEqual(currentURL(), '/vault/auth?with=token');
    for (const backend of backends.reverse()) {
      await component.selectMethod(backend.type);
      assert.strictEqual(
        currentURL(),
        `/vault/auth?with=${backend.type}`,
        `has the correct URL for ${backend.type}`
      );
    }
  });

  test('it clears token when changing selected auth method', async function (assert) {
    await visit('/vault/auth');
    assert.strictEqual(currentURL(), '/vault/auth?with=token');
    await component.token('token').selectMethod('github');
    await component.selectMethod('token');
    assert.strictEqual(component.tokenValue, '', 'it clears the token value when toggling methods');
  });

  test('it sends the right attributes when authenticating', async function (assert) {
    assert.expect(6);
    const backends = supportedAuthBackends();
    await visit('/vault/auth');
    for (const backend of backends.reverse()) {
      await component.selectMethod(backend.type);
      if (backend.type === 'github') {
        await component.token('token');
      }
      if (backend.type === 'jwt' || backend.type === 'oidc') {
        await jwtComponent.role('test');
      }
      await component.login();
      const lastRequest = this.server.passthroughRequests[this.server.passthroughRequests.length - 1];
      let body = JSON.parse(lastRequest.requestBody);
      // Note: x-vault-token used to be lowercase prior to upgrade
      if (backend.type === 'token') {
        assert.ok(
          Object.keys(lastRequest.requestHeaders).includes('X-Vault-Token'),
          'token uses OpenBao token header'
        );
      } else if (backend.type === 'github') {
        assert.ok(Object.keys(body).includes('token'), 'GitHub includes token');
      } else if (backend.type === 'jwt' || backend.type === 'oidc') {
        const authReq = this.server.passthroughRequests[this.server.passthroughRequests.length - 2];
        body = JSON.parse(authReq.requestBody);
        assert.ok(Object.keys(body).includes('role'), `${backend.type} includes role`);
      } else {
        assert.ok(Object.keys(body).includes('password'), `${backend.type} includes password`);
      }
    }
  });

  test('it shows the push notification warning after submit', async function (assert) {
    assert.expect(1);

    this.server.get('/v1/auth/token/lookup-self', async () => {
      assert.ok(
        await waitUntil(() => find('[data-test-auth-message="push"]')),
        'shows push notification message'
      );
      return [204, { 'Content-Type': 'application/json' }, JSON.stringify({})];
    });

    await visit('/vault/auth');
    await component.selectMethod('token');
    await click('[data-test-auth-submit]');
  });
});
