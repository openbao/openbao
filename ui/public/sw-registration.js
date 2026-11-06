/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

if ('serviceWorker' in navigator) {
  navigator.serviceWorker
    .register('/ui/sw.js', {
      scope: '/v1/sys/storage/raft/snapshot',
    })
    .then(function (registration) {
      window.addEventListener('pagehide', function (event) {
        if (event.persisted) {
          return;
        }
        registration.unregister();
      });
    })
    .catch(function () {});
}
