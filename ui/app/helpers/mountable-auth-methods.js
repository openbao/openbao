/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { helper as buildHelper } from '@ember/component/helper';

const MOUNTABLE_AUTH_METHODS = [
  {
    displayName: 'AppRole',
    value: 'approle',
    type: 'approle',
    category: 'generic',
  },
  {
    displayName: 'JWT',
    value: 'jwt',
    type: 'jwt',
    glyph: 'auth',
    category: 'generic',
  },
  {
    displayName: 'OIDC',
    value: 'oidc',
    type: 'oidc',
    glyph: 'auth',
    category: 'generic',
  },
  {
    displayName: 'Kubernetes',
    value: 'kubernetes',
    type: 'kubernetes',
    category: 'infra',
    glyph: 'kubernetes-color',
  },
  {
    displayName: 'LDAP',
    value: 'ldap',
    type: 'ldap',
    glyph: 'auth',
    category: 'infra',
  },
  {
    displayName: 'RADIUS',
    value: 'radius',
    type: 'radius',
    glyph: 'auth',
    category: 'infra',
  },
  {
    displayName: 'TLS Certificates',
    value: 'cert',
    type: 'cert',
    category: 'generic',
  },
  {
    displayName: 'Username & Password',
    value: 'userpass',
    type: 'userpass',
    category: 'generic',
  },
];

export function methods() {
  return MOUNTABLE_AUTH_METHODS.slice();
}

export default buildHelper(methods);
