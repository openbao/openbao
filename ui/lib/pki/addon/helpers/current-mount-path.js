/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Helper from '@ember/component/helper';

// Returns the path of the currently viewed secret mount
export default class CurrentMountPathHelper extends Helper {
  @service secretMountPath;

  compute() {
    return this.secretMountPath.currentPath;
  }
}
