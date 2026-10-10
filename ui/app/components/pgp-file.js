/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@ember/component';
import { set, action } from '@ember/object';
import { run } from '@ember/runloop';
import { task } from 'ember-concurrency';
import { waitFor } from '@ember/test-waiters';

const BASE_64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/gi;

export default class PgpFileComponent extends Component {
  'data-test-pgp-file' = true;
  attributeBindings = ['data-test-pgp-file'];
  classNames = ['box', 'is-fullwidth', 'is-marginless', 'is-shadowless'];

  key = null;
  index = null;
  onChange = () => {};
  label = null;
  fileHelpText = null;
  textareaHelpText = null;

  readNativeFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();

      reader.onload = () => run(() => resolve(reader.result));
      reader.onerror = (error) => run(() => reject(error));

      reader.readAsDataURL(file);
    });
  }

  @task
  @waitFor
  *processFile(file) {
    const dataURL = yield this.readNativeFile(file);
    yield this.setPGPKey.perform(dataURL, file.name);
  }

  @task
  @waitFor
  *setPGPKey(dataURL, filename) {
    const b64File = dataURL.split(',')[1].trim();
    const decoded = atob(b64File).trim();

    const fileData = decoded.match(BASE_64_REGEX) ? decoded : b64File;
    yield this.onChange(this.index, { value: fileData, filename: filename });
  }

  @action
  toggleText() {
    set(this, 'key.enterAsText', !this.key.enterAsText);
  }

  @action
  pickedFile(e) {
    const { files } = e.target;
    if (!files || !files.length) {
      return;
    }
    for (let i = 0, len = files.length; i < len; i++) {
      this.processFile.perform(files[i]);
    }
  }

  @action
  updateData(e) {
    set(this.key, 'value', e.target.value);
    this.onChange(this.index, this.key);
  }

  @action
  clearKey() {
    this.onChange(this.index, { value: '' });
  }
}
