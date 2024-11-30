/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { resolve } from 'rsvp';
import { module, test } from 'qunit';
import { setupTest } from 'ember-qunit';

module('Unit | Adapter | cluster', function (hooks) {
  setupTest(hooks);

  test('cluster api urls', function (assert) {
    let url, method, options;
    const adapter = this.owner.factoryFor('adapter:cluster').create({
      ajax: (...args) => {
        [url, method, options] = args;
        return resolve();
      },
    });
    adapter.health();
    assert.strictEqual(url, '/v1/sys/health', 'health url OK');
    assert.deepEqual(
      {
        standbycode: 200,
        sealedcode: 200,
        uninitcode: 200,
        drsecondarycode: 200,
        performancestandbycode: 200,
      },
      options.data,
      'health data params OK'
    );
    assert.strictEqual(method, 'GET', 'health method OK');

    adapter.sealStatus();
    assert.strictEqual(url, '/v1/sys/seal-status', 'health url OK');
    assert.strictEqual(method, 'GET', 'seal-status method OK');

    let data = { someData: 1 };
    adapter.unseal(data);
    assert.strictEqual(url, '/v1/sys/unseal', 'unseal url OK');
    assert.strictEqual(method, 'PUT', 'unseal method OK');
    assert.deepEqual({ data, unauthenticated: true }, options, 'unseal options OK');

    adapter.initCluster(data);
    assert.strictEqual(url, '/v1/sys/init', 'init url OK');
    assert.strictEqual(method, 'PUT', 'init method OK');
    assert.deepEqual({ data, unauthenticated: true }, options, 'init options OK');

    data = { token: 'token', password: 'password', username: 'username' };

    adapter.authenticate({ backend: 'token', data });
    assert.strictEqual(url, '/v1/auth/token/lookup-self', 'auth:token url OK');
    assert.strictEqual(method, 'GET', 'auth:token method OK');
    assert.deepEqual(
      { headers: { 'X-Vault-Token': 'token' }, unauthenticated: true },
      options,
      'auth:token options OK'
    );

    adapter.authenticate({ backend: 'github', data });
    assert.strictEqual(url, '/v1/auth/github/login', 'auth:github url OK');
    assert.strictEqual(method, 'POST', 'auth:github method OK');
    assert.deepEqual(
      { data: { password: 'password', token: 'token' }, unauthenticated: true },
      options,
      'auth:github options OK'
    );

    data = { jwt: 'token', role: 'test' };
    adapter.authenticate({ backend: 'jwt', data });
    assert.strictEqual(url, '/v1/auth/jwt/login', 'auth:jwt url OK');
    assert.strictEqual(method, 'POST', 'auth:jwt method OK');
    assert.deepEqual(
      { data: { jwt: 'token', role: 'test' }, unauthenticated: true },
      options,
      'auth:jwt options OK'
    );

    data = { jwt: 'token', role: 'test', path: 'oidc' };
    adapter.authenticate({ backend: 'jwt', data });
    assert.strictEqual(url, '/v1/auth/oidc/login', 'auth:jwt custom mount path, url OK');

    data = { token: 'token', password: 'password', username: 'username', path: 'path' };

    adapter.authenticate({ backend: 'token', data });
    assert.strictEqual(url, '/v1/auth/token/lookup-self', 'auth:token url with path OK');

    adapter.authenticate({ backend: 'github', data });
    assert.strictEqual(url, '/v1/auth/path/login', 'auth:github with path url OK');

    data = { password: 'password', username: 'username' };

    adapter.authenticate({ backend: 'userpass', data });
    assert.strictEqual(url, '/v1/auth/userpass/login/username', 'auth:userpass url OK');
    assert.strictEqual(method, 'POST', 'auth:userpass method OK');
    assert.deepEqual(
      { data: { password: 'password' }, unauthenticated: true },
      options,
      'auth:userpass options OK'
    );

    adapter.authenticate({ backend: 'radius', data });
    assert.strictEqual(url, '/v1/auth/radius/login/username', 'auth:RADIUS url OK');
    assert.strictEqual(method, 'POST', 'auth:RADIUS method OK');
    assert.deepEqual(
      { data: { password: 'password' }, unauthenticated: true },
      options,
      'auth:RADIUS options OK'
    );

    adapter.authenticate({ backend: 'LDAP', data });
    assert.strictEqual(url, '/v1/auth/ldap/login/username', 'ldap:userpass url OK');
    assert.strictEqual(method, 'POST', 'ldap:userpass method OK');
    assert.deepEqual(
      { data: { password: 'password' }, unauthenticated: true },
      options,
      'ldap:userpass options OK'
    );

    data = { password: 'password', username: 'username', nonce: 'uuid' };
    adapter.authenticate({ backend: 'okta', data });
    assert.strictEqual(url, '/v1/auth/okta/login/username', 'okta:userpass url OK');
    assert.strictEqual(method, 'POST', 'ldap:userpass method OK');
    assert.deepEqual(
      { data: { password: 'password', nonce: 'uuid' }, unauthenticated: true },
      options,
      'okta:userpass options OK'
    );

    // use a custom mount path
    data = { password: 'password', username: 'username', path: 'path' };

    adapter.authenticate({ backend: 'userpass', data });
    assert.strictEqual(url, '/v1/auth/path/login/username', 'auth:userpass with path url OK');

    adapter.authenticate({ backend: 'LDAP', data });
    assert.strictEqual(url, '/v1/auth/path/login/username', 'auth:LDAP with path url OK');

    data = { password: 'password', username: 'username', path: 'path', nonce: 'uuid' };
    adapter.authenticate({ backend: 'Okta', data });
    assert.strictEqual(url, '/v1/auth/path/login/username', 'auth:Okta with path url OK');
  });
});
