/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@glimmer/component';
import { assert } from '@ember/debug';

export interface SidebarHeaderHomeLinkSignature {
  Args: {
    ariaLabel: string;
  };
}

export default class SidebarHeaderHomeLinkComponent extends Component<SidebarHeaderHomeLinkSignature> {
  /**
   * @param ariaLabel
   * @type {string}
   * @description The value of `aria-label`
   */
  get ariaLabel() {
    const { ariaLabel } = this.args;

    assert(
      '@ariaLabel for "Sidebar::Header::HomeLink" ("Logo") must have a valid value',
      ariaLabel !== undefined
    );

    return ariaLabel;
  }
}
