/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

module.exports = {
  name: require('./package').name,
  isDevelopingAddon() {
    return true;
  },
};
