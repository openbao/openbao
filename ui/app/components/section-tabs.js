/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@ember/component';

export default class SectionTabs extends Component {
  tagName = '';
  model = null;
  tabType = 'authSettings';

  static positionalParams = ['model', 'tabType', 'paths'];
}
