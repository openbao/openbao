/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import ENV from 'vault/config/environment';
const { handler } = ENV['ember-cli-mirage'];
import kubernetesScenario from './kubernetes';

export default function (server) {
  server.create('clients/config');
  if (handler === 'kubernetes') {
    kubernetesScenario(server);
  }
}
