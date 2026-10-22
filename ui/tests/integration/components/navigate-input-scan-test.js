// SPDX-License-Identifier: MPL-2.0

import { module, test } from 'qunit';
import { setupRenderingTest } from 'ember-qunit';
import { render, triggerKeyEvent } from '@ember/test-helpers';
import hbs from 'htmlbars-inline-precompile';
import sinon from 'sinon';

module('Integration | Component | navigate-input scan', function (hooks) {
  setupRenderingTest(hooks);

  test('Ctrl+Enter scans the selected folder or the root', async function (assert) {
    const router = this.owner.lookup('service:host-router');
    router.transitionTo = sinon.stub();
    this.set('filter', 'team/');

    await render(
      hbs`<NavigateInput @filter={{this.filter}} @scanRoute="vault.cluster.secrets.backend.scan" />`
    );
    await triggerKeyEvent('[data-test-component="navigate-input"]', 'keyup', 13, { ctrlKey: true });
    assert.deepEqual(router.transitionTo.firstCall.args, [
      'vault.cluster.secrets.backend.scan',
      'team/',
      { queryParams: { page: 1, pageFilter: null } },
    ]);

    this.set('filter', 'plain-key');
    await triggerKeyEvent('[data-test-component="navigate-input"]', 'keyup', 13, { ctrlKey: true });
    assert.deepEqual(router.transitionTo.secondCall.args, [
      'vault.cluster.secrets.backend.scan-root',
      { queryParams: { page: 1, pageFilter: 'plain-key' } },
    ]);
  });
});
