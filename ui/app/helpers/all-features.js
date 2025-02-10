/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { helper as buildHelper } from '@ember/component/helper';

const ALL_FEATURES = [
  'HSM',
  'MFA',
  'Seal Wrapping',
  'Control Groups',
  'Performance Standby',
  'Namespaces',
  'KMIP',
  'Entropy Augmentation',
  'Transform Secrets Engine',
];

export function allFeatures() {
  return ALL_FEATURES;
}

export default buildHelper(allFeatures);
