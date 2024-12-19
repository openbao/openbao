/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { attr } from '@ember-data/model';
import { withFormFields } from 'vault/decorators/model-form-fields';
import lazyCapabilities, { apiPath } from 'vault/macros/lazy-capabilities';

const formFieldGroups = [
  {
    'Certificate Revocation List (CRL)': ['expiry', 'autoRebuildGracePeriod', 'deltaRebuildInterval'],
  },
  {
    'Online Certificate Status Protocol (OCSP)': ['ocspExpiry'],
  },
];
@withFormFields(null, formFieldGroups)
export default class PkiConfigCrlModel extends Model {
  // This model uses the backend value as the model ID

  @attr('boolean') autoRebuild;
  @attr('string', {
    label: 'Auto-rebuild on',
    labelDisabled: 'Auto-rebuild off',
    mapToBoolean: 'autoRebuild',
    isOppositeValue: false,
    editType: 'ttl',
    helperTextEnabled: 'OpenBao will rebuild the CRL in the below grace period before expiration',
    helperTextDisabled: 'OpenBao will not automatically rebuild the CRL',
  })
  autoRebuildGracePeriod;

  @attr('boolean') enableDelta;
  @attr('string', {
    label: 'Delta CRL building on',
    labelDisabled: 'Delta CRL building off',
    mapToBoolean: 'enableDelta',
    isOppositeValue: false,
    editType: 'ttl',
    helperTextEnabled: 'OpenBao will rebuild the delta CRL at the interval below:',
    helperTextDisabled: 'OpenBao will not rebuild the delta CRL at an interval',
  })
  deltaRebuildInterval;

  @attr('boolean') disable;
  @attr('string', {
    label: 'Expiry',
    labelDisabled: 'No expiry',
    mapToBoolean: 'disable',
    isOppositeValue: true,
    editType: 'ttl',
    helperTextDisabled: 'The CRL will not be built.',
    helperTextEnabled: 'The CRL will expire after:',
  })
  expiry;

  @attr('boolean') ocspDisable;
  @attr('string', {
    label: 'OCSP responder APIs enabled',
    labelDisabled: 'OCSP responder APIs disabled',
    mapToBoolean: 'ocspDisable',
    isOppositeValue: true,
    editType: 'ttl',
    helperTextEnabled: "Requests about a certificate's status will be valid for:",
    helperTextDisabled: 'Requests cannot be made to check if an individual certificate is valid.',
  })
  ocspExpiry;

  @lazyCapabilities(apiPath`${'id'}/config/crl`, 'id') crlPath;

  get canSet() {
    return this.crlPath.get('canUpdate') !== false;
  }
}
