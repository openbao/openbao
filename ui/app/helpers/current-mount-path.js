/**
 * Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
 * SPDX-License-Identifier: MPL-2.0
 */

import Helper from '@ember/component/helper';
import { service } from '@ember/service';

// Returns the path of the currently viewed secret mount
export default class CurrentMountPathHelper extends Helper {
  @service secretMountPath;

  compute() {
    return this.secretMountPath.currentPath;
  }
}
