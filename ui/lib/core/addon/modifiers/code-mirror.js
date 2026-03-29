/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { action } from '@ember/object';
import { bind } from '@ember/runloop';
import codemirror from 'codemirror';
import Modifier from 'ember-modifier';

import 'codemirror/addon/edit/matchbrackets';
import 'codemirror/addon/selection/active-line';
import 'codemirror/addon/lint/lint.js';
import 'codemirror/addon/lint/json-lint.js';
// right now we only use the ruby and javascript, if you use another mode you'll need to import it.
// https://codemirror.net/mode/
import 'codemirror/mode/ruby/ruby';
import 'codemirror/mode/javascript/javascript';

export default class CodeMirrorModifier extends Modifier {
  named = null;

  modify(element, positional, named) {
    this.named = named;
    if (this._editor == null) {
      this._setup(element, named);
      return;
    }

    this._editor.setOption('readOnly', named.readOnly);
    if (!named.content) {
      return;
    }
    if (this._editor.getValue() !== named.content) {
      this._editor.setValue(named.content);
    }
  }

  @action
  _onChange(editor) {
    // avoid sending change event after initial setup when editor value is set to content
    if (this.named.content !== editor.getValue()) {
      this.named.onUpdate(editor.getValue(), this._editor);
    }
  }

  @action
  _onFocus(editor) {
    this.named.onFocus(editor.getValue());
  }

  _setup(element, named) {
    if (!element) {
      throw new Error('CodeMirror modifier has no element');
    }
    const editor = codemirror(element, {
      // IMPORTANT: `gutters` must come before `lint` since the presence of
      // `gutters` is cached internally when `lint` is toggled
      gutters: named.gutters || ['CodeMirror-lint-markers'],
      matchBrackets: true,
      lint: { lintOnChange: true },
      showCursorWhenSelecting: true,
      styleActiveLine: true,
      tabSize: 2,
      // all values we can pass into the JsonEditor
      extraKeys: named.extraKeys || '',
      lineNumbers: named.lineNumbers,
      mode: named.mode || 'application/json',
      readOnly: named.readOnly || false,
      theme: named.theme || 'hashi',
      value: named.content || '',
      viewportMargin: named.viewportMargin || '',
    });

    editor.on('change', bind(this, this._onChange));
    editor.on('focus', bind(this, this._onFocus));

    this._editor = editor;
  }
}
