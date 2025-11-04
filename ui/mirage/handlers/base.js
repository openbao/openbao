/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

export default function (server) {
  server.get('/sys/health', function () {
    return {
      initialized: true,
      sealed: false,
      standby: false,
      license: {
        expiry: '2021-05-12T23:20:50.52Z',
        state: 'stored',
      },
      performance_standby: false,
      server_time_utc: 1622562585,
      version: '1.9.0+ent',
      cluster_name: 'vault-cluster-e779cd7c',
      cluster_id: '5f20f5ab-acea-0481-787e-71ec2ff5a60b',
      last_wal: 121,
    };
  });

  server.get('sys/namespaces', function () {
    return {
      data: {
        keys: [
          'ns1/',
          'ns2/',
          'ns3/',
          'ns4/',
          'ns5/',
          'ns6/',
          'ns7/',
          'ns8/',
          'ns9/',
          'ns10/',
          'ns11/',
          'ns12/',
          'ns13/',
          'ns14/',
          'ns15/',
          'ns16/',
          'ns17/',
          'ns18/',
        ],
      },
    };
  });
}
