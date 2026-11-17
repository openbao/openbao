/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/**
 * @module ReadonlyFormField
 * ReadonlyFormField components are used to...
 *
 * @example
 * ```js
 * <ReadonlyFormField @attr={attr} />
 * ```
 * @param {object} attr - Should be an attribute from a model exported with expandAttributeMeta
 * @param {any} value - The value that should be displayed on the input
 */

import Component from '@glimmer/component';
import { capitalize, dasherize } from '@ember/string';
import { humanize } from 'vault/helpers/humanize';

export default class ReadonlyFormField extends Component {
  get labelString() {
    if (!this.args.attr) {
      return '';
    }
    const label = this.args.attr.options ? this.args.attr.options.label : '';
    const name = this.args.attr.name;
    if (label) {
      return label;
    }
    if (name) {
      return capitalize(humanize([dasherize(name)]));
    }
    return '';
  }
}
