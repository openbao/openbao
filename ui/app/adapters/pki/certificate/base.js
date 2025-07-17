/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { encodePath } from 'vault/utils/path-encoding-helpers';
import ApplicationAdapter from '../../application';

export default class PkiCertificateBaseAdapter extends ApplicationAdapter {
  namespace = 'v1';

  getURL(backend, id) {
    const uri = `${this.buildURL()}/${encodePath(backend)}`;
    return id ? `${uri}/cert/${id}` : `${uri}/certs/detailed`;
  }

  async fetchByQuery(query) {
    const { backend, id } = query;
    const data = !id ? { list: true } : {};
    const uri = `${this.buildURL()}/${encodePath(backend)}`;
    if (!id) {
      try {
        const resp = await this.ajax(`${uri}/certs/detailed`, 'GET', {
          data: { list: true },
        });
        resp.data.backend = backend;
        return resp;
      } catch (err) {
        // fallback to regular /certs
        const fallbackResp = await this.ajax(`${uri}/certs`, 'GET', {
          data: { list: true },
        });
        fallbackResp.data.backend = backend;
        return fallbackResp;
      }
    } else {
      return this.ajax(`${uri}/cert/${id}`, 'GET', { data }).then((resp) => {
        resp.data.backend = backend;
        resp.data.id = id;
        resp.data.serial_number = id;
        return resp;
      });
    }
  }

  query(store, type, query) {
    return this.fetchByQuery(query);
  }

  queryRecord(store, type, query) {
    return this.fetchByQuery(query);
  }

  // the only way to update a record is by revoking it which will set the revocationTime property
  updateRecord(store, type, snapshot) {
    const { backend, serialNumber, certificate } = snapshot.record;
    // Revoke certificate requires either serial_number or certificate
    const data = serialNumber ? { serial_number: serialNumber } : { certificate };
    return this.ajax(`${this.buildURL()}/${encodePath(backend)}/revoke`, 'POST', { data }).then(
      (response) => {
        return {
          data: {
            ...this.serialize(snapshot),
            ...response.data,
          },
        };
      }
    );
  }
}
