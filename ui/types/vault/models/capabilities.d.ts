/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model from '@ember-data/model';

interface CapabilitiesModel extends Model {
  path: string;
  capabilities: Array<string>;
  canSudo: boolean | undefined;
  canRead: boolean | undefined;
  canCreate: boolean | undefined;
  canUpdate: boolean | undefined;
  canDelete: boolean | undefined;
  canList: boolean | undefined;
  // these don't seem to be used anywhere
  // inferring type from key name
  allowedParameters: Array<string>;
  deniedParameters: Array<string>;
}

export default CapabilitiesModel;
export const SUDO_PATHS: string[];
export const SUDO_PATH_PREFIXES: string[];
