/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Application from 'vault/adapters/application';
import Adapter from '@ember-data/adapter';
import ModelRegistry from '@ember-data/types/registries/model';
import PkiIssuerAdapter from 'vault/adapters/pki/issuer';
import PkiTidyAdapter from 'vault/adapters/pki/tidy';

/**
 * Catch-all for ember-data.
 */
export default interface AdapterRegistry {
  'pki/issuer': PkiIssuerAdapter;
  'pki/tidy': PkiTidyAdapter;
  application: Application;
  [key: keyof ModelRegistry]: Adapter;
}
