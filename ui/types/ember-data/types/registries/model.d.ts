/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import PkiActionModel from 'vault/models/pki/action';
import PkiCertificateGenerateModel from 'vault/models/pki/certificate/generate';

declare module 'ember-data/types/registries/model' {
  export default interface ModelRegistry {
    'pki/action': PkiActionModel;
    'pki/certificate/generate': PkiCertificateGenerateModel;
    // Catchall for any other models
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any;
  }
}
