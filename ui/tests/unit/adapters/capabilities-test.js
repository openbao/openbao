/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import AdapterError from '@ember-data/adapter/error';
import { reject, resolve } from 'rsvp';
import { module, test } from 'qunit';
import { setupTest } from 'ember-qunit';

module('Unit | Adapter | capabilities', function (hooks) {
  setupTest(hooks);

  test('calls the correct url', function (assert) {
    let url, method, options;
    const adapter = this.owner.factoryFor('adapter:capabilities').create({
      ajax: (...args) => {
        [url, method, options] = args;
        return resolve();
      },
    });

    adapter.findRecord(null, 'capabilities', 'foo');
    assert.strictEqual(url, '/v1/sys/capabilities-self', 'calls the correct URL');
    assert.deepEqual({ paths: ['foo'] }, options.data, 'data params OK');
    assert.strictEqual(method, 'POST', 'method OK');
  });

  // the check always happens in the namespace the token was issued in, so the path
  // is qualified with the namespace being browsed, relative to that one
  [
    ['the root namespace', '', '', 'foo'],
    ['a child namespace', '', 'org', 'org/foo'],
    ['a nested child namespace', '', 'org/team', 'org/team/foo'],
    ['the token namespace', 'org', 'org', 'foo'],
    ['a child of the token namespace', 'org', 'org/team', 'team/foo'],
    ['a sibling of the token namespace', 'org', 'organization', 'organization/foo'],
  ].forEach(([description, userRootNamespace, path, expectedPath]) => {
    test(`browsing ${description}`, function (assert) {
      let options;
      const adapter = this.owner.factoryFor('adapter:capabilities').create({
        namespaceService: { userRootNamespace, path },
        ajax: (...args) => {
          options = args[2];
          return resolve();
        },
      });

      adapter.findRecord(null, 'capabilities', 'foo');
      assert.deepEqual({ paths: [expectedPath] }, options.data, `asks about ${expectedPath}`);
      assert.strictEqual(options.namespace, userRootNamespace, 'asks in the token namespace');
    });
  });

  test('reports the unqualified policy path when the request is denied', async function (assert) {
    assert.expect(1);
    const adapter = this.owner.factoryFor('adapter:capabilities').create({
      namespaceService: { userRootNamespace: '', path: 'org' },
      ajax: () => reject(new AdapterError()),
    });

    await adapter.findRecord(null, 'capabilities', 'foo').catch((e) => {
      assert.strictEqual(e.policyPath, 'sys/capabilities-self', 'policyPath is not namespaced');
    });
  });
});
