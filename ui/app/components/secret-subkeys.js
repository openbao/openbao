/**
 * SPDX-License-Identifier: MPL-2.0
 */

import { action } from '@ember/object';
import { guidFor } from '@ember/object/internals';
import { inject as service } from '@ember/service';
import Component from '@glimmer/component';
import { cached, tracked } from '@glimmer/tracking';
import keyUtils from 'vault/lib/key-utils';

export default class SecretSubkeys extends Component {
  @service store;
  @service flashMessages;

  @tracked editing;
  @tracked newValue = '';
  @tracked jsonValue = false;
  @tracked isSaving = false;
  @tracked error;

  @cached
  get keys() {
    const viewId = guidFor(this.args.data.view);
    return this.args.data.paths.map((path) => ({
      id: JSON.stringify([viewId, path]),
      path,
      label: path.length === 1 && path[0] ? path[0] : JSON.stringify(path),
      spaceWarning: keyUtils.keyWhitespaceWarning(path.at(-1)),
    }));
  }

  get editingKey() {
    return this.isCurrentView(this.editing?.data) ? this.editing.key : null;
  }

  @cached
  get displayedValues() {
    return this.keys.map(({ path }) => {
      const value = path.reduce((current, key) => current?.[key], this.args.values);
      return typeof value === 'string' ? value : JSON.stringify(value);
    });
  }

  isCurrentView(data) {
    return data?.view === this.args.data.view && data?.patchVersion === this.args.data.patchVersion;
  }

  @action
  edit(key) {
    this.newValue = '';
    this.jsonValue = false;
    this.error = null;
    this.editing = { data: this.args.data, key: key.id };
  }

  @action
  cancel() {
    this.newValue = '';
    this.editing = null;
    this.error = null;
  }

  @action
  save(key, event) {
    event.preventDefault();
    if (key.id !== this.editingKey) {
      return;
    }
    let value = this.newValue;
    if (this.jsonValue) {
      try {
        value = JSON.parse(value);
      } catch {
        this.error = { key: key.id, message: 'Enter a valid JSON value.' };
        return;
      }
      if (value === null) {
        this.error = { key: key.id, message: 'Use the Delete action to remove this key.' };
        return;
      }
    }

    return this.patch(this.args.data, key, value);
  }

  @action
  async patch(data, key, value) {
    const { backend, path } = this.args;
    if (!this.isCurrentView(data) || !data.patchVersion || this.isSaving) {
      return;
    }

    this.error = null;
    const patch = key.path.reduceRight((nested, name) => ({ [name]: nested }), value);
    this.isSaving = true;
    try {
      const adapter = this.store.adapterFor('secret-v2-version');
      await adapter.patchSecret(backend, path, data.patchVersion, patch);
    } catch (error) {
      if (!this.isDestroying && this.isCurrentView(data)) {
        this.error = { key: key.id, message: error.errors?.join('. ') || 'Could not update the subkey.' };
      }
      return;
    } finally {
      this.isSaving = false;
    }

    if (!this.isDestroying && this.isCurrentView(data)) {
      this.cancel();
      this.flashMessages.success(value === null ? 'Subkey deleted.' : 'Subkey updated.');
      this.args.onSaved();
    }
  }
}
