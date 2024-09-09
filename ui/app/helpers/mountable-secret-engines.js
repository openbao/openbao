/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { helper as buildHelper } from '@ember/component/helper';

const MOUNTABLE_SECRET_ENGINES = [
  {
    displayName: 'Databases',
    type: 'database',
    category: 'infra',
  },
  {
    displayName: 'KV',
    type: 'kv',
    category: 'generic',
  },
  {
    displayName: 'PKI Certificates',
    type: 'pki',
    engineRoute: 'pki.overview',
    category: 'generic',
  },
  {
    displayName: 'RabbitMQ',
    type: 'rabbitmq',
    category: 'infra',
  },
  {
    displayName: 'SSH',
    type: 'ssh',
    category: 'generic',
  },
  {
    displayName: 'Transit',
    type: 'transit',
    category: 'generic',
  },
  {
    displayName: 'TOTP',
    type: 'totp',
    category: 'generic',
  },
  {
    displayName: 'Kubernetes',
    value: 'kubernetes',
    type: 'kubernetes',
    engineRoute: 'kubernetes.overview',
    category: 'generic',
    glyph: 'kubernetes-color',
  },
];

export function mountableEngines() {
  return MOUNTABLE_SECRET_ENGINES.slice();
}

export function allEngines() {
  return [...MOUNTABLE_SECRET_ENGINES];
}

export default buildHelper(mountableEngines);
