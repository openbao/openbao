/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { module, test } from 'qunit';
import { setupApplicationTest } from 'ember-qunit';
import { create } from 'ember-cli-page-object';
import { fillIn } from '@ember/test-helpers';
import { v4 as uuidv4 } from 'uuid';

import enablePage from 'vault/tests/pages/settings/auth/enable';
import page from 'vault/tests/pages/settings/auth/configure/section';
import indexPage from 'vault/tests/pages/settings/auth/configure/index';
import apiStub from 'vault/tests/helpers/noop-all-api-requests';
import consolePanel from 'vault/tests/pages/components/console/ui-panel';
import authPage from 'vault/tests/pages/auth';

const cli = create(consolePanel);

module('Acceptance | settings/auth/configure/section', function (hooks) {
  setupApplicationTest(hooks);

  hooks.beforeEach(function () {
    this.uid = uuidv4();
    this.server = apiStub({ usePassthrough: true });
    return authPage.login();
  });

  hooks.afterEach(function () {
    this.server.shutdown();
  });

  test('it can save options', async function (assert) {
    const path = `approle-save-${this.uid}`;
    const type = 'approle';
    const section = 'options';
    await enablePage.enable(type, path);
    await page.visit({ path, section });
    await page.fillInTextarea('description', 'This is AppRole!');
    assert
      .dom('[data-test-input="config.tokenType"]')
      .hasValue('default-service', 'as default the token type selected is default-service.');
    await fillIn('[data-test-input="config.tokenType"]', 'batch');
    await page.save();
    assert.strictEqual(
      page.flash.latestMessage,
      `The configuration was saved successfully.`,
      'success flash shows'
    );
    const tuneRequest = this.server.passthroughRequests.filterBy(
      'url',
      `/v1/sys/mounts/auth/${path}/tune`
    )[0];
    const keys = Object.keys(JSON.parse(tuneRequest.requestBody));
    const token_type = JSON.parse(tuneRequest.requestBody).token_type;
    assert.strictEqual(token_type, 'batch', 'passes new token type');
    assert.ok(keys.includes('default_lease_ttl'), 'passes default_lease_ttl on tune');
    assert.ok(keys.includes('max_lease_ttl'), 'passes max_lease_ttl on tune');
    assert.ok(keys.includes('description'), 'passes updated description on tune');
  });

  for (const type of ['ldap', 'kubernetes']) {
    test(`it shows tabs for auth method: ${type}`, async function (assert) {
      const path = `${type}-showtab-${this.uid}`;
      await cli.consoleInput(`write sys/auth/${path} type=${type}`);
      await cli.enter();
      await indexPage.visit({ path });
      // items will have 'Configuration' and 'Method Options' tabs
      const numTabs = 2;
      assert.strictEqual(page.tabs.length, numTabs, 'shows correct number of tabs');
    });
  }
});
