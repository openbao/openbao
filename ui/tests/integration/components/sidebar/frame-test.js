import { module, test } from 'qunit';
import { setupRenderingTest } from 'ember-qunit';
import { render, click } from '@ember/test-helpers';
import hbs from 'htmlbars-inline-precompile';

module('Integration | Component | sidebar-frame', function (hooks) {
  setupRenderingTest(hooks);

  test('it should hide and show sidebar', async function (assert) {
    this.set('showSidebar', true);
    await render(hbs`
      <Sidebar::Frame @showSidebar={{this.showSidebar}} />
    `);
    assert.dom('[data-test-sidebar-nav]').exists('Sidebar renders');

    this.set('showSidebar', false);
    assert.dom('[data-test-sidebar-nav]').doesNotExist('Sidebar is hidden');
  });

  test('it should render console ui panel and yield block for app content', async function (assert) {
    const currentCluster = this.owner.lookup('service:currentCluster');
    currentCluster.setCluster({});
    const version = this.owner.lookup('service:version');
    version.version = '1.13.0-dev1+ent';

    await render(hbs`
      <Sidebar::Frame @showSidebar={{true}}>
        <div class="page-container">
          App goes here!
        </div>
      </Sidebar::Frame>
    `);

    assert.dom('[data-test-component="console/ui-panel"]').exists('Console UI panel renders');
    assert.dom('.page-container').exists('Block yields for app content');
  });

  test('it should render logo and actions in sidebar header', async function (assert) {
    this.owner.lookup('service:currentCluster').setCluster({ name: 'vault' });

    await render(hbs`
      <Sidebar::Frame @showSidebar={{true}} />
    `);

    assert.dom('[data-test-sidebar-logo]').exists('OpenBao logo renders in sidebar header');
    assert.dom('[data-test-console-toggle]').exists('Console toggle button renders in sidebar header');
    await click('[data-test-console-toggle]');
    assert.dom('.panel-open').exists('Console ui panel opens');
    await click('[data-test-console-toggle]');
    assert.dom('.panel-open').doesNotExist('Console ui panel closes');
    assert.dom('[data-test-user-menu]').exists('User menu renders');
  });
});
