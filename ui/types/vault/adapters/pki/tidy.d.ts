/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { AdapterRegistry } from '@ember-data/adapter';

export default interface PkiTidyAdapter extends AdapterRegistry {
  namespace: string;
  cancelTidy(backend: string);
}
