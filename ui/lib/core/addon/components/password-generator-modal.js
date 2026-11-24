import Component from '@glimmer/component';
import { action } from '@ember/object';
import { guidFor } from '@ember/object/internals';
import { tracked } from '@glimmer/tracking';
import generatePassword, { DEFAULT_LENGTH, MIN_LENGTH, MAX_LENGTH } from 'core/utils/generate-password';

export default class PasswordGeneratorModal extends Component {
  idPrefix = 'pw-gen' + guidFor(this);
  minLen = MIN_LENGTH;
  maxLen = MAX_LENGTH;

  // Modal checklist for character types
  typeOptions = [
    { key: 'lower', label: 'Lowercase (a-z)' },
    { key: 'upper', label: 'Uppercase (A-Z)' },
    { key: 'digits', label: 'Numbers (0-9)' },
    { key: 'symbols', label: 'Symbols (!@#$%^&*()_+~)' },
  ];

  @tracked len = DEFAULT_LENGTH;
  @tracked types = { lower: true, upper: true, digits: true, symbols: true };
  @tracked pw = '';
  @tracked error = null;

  // Generates a password
  constructor() {
    super(...arguments);
    this.regenerate();
  }

  // Password setting changes will result in a regenerated password
  @action regenerate() {
    try {
      this.pw = generatePassword({
        length: this.length,
        ...this.types,
      });
      this.error = null;
    } catch (e) {
      this.pw = '';
      this.error = e.message;
    }
  }

  @action setLength(event) {
    this.len = Number(event.target.value);
    this.regenerate();
  }

  @action toggleType(key, event) {
    this.types = { ...this.types, [key]: event.target.checked };
    this.regenerate();
  }

  @action use() {
    if (!this.pw) return;
    this.args.onUse(this.pw);
  }
}
