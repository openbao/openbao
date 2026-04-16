/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { parseCertificate } from 'vault/utils/parse-pki-cert';
import ApplicationSerializer from '../../application';

export default class PkiCertificateBaseSerializer extends ApplicationSerializer {
  primaryKey = 'serial_number';

  attrs = {
    role: { serialize: false },
  };

  normalizeResponse(store, primaryModelClass, payload, id, requestType) {
    if (payload.data.certificate) {
      // Parse certificate back from the API and add to payload
      const parsedCert = parseCertificate(payload.data.certificate);
      return super.normalizeResponse(
        store,
        primaryModelClass,
        { ...payload, parsed_certificate: parsedCert, common_name: parsedCert.common_name },
        id,
        requestType
      );
    }
    return super.normalizeResponse(...arguments);
  }

  // rehydrate each cert model so all model attributes are accessible from the LIST response
  normalizeItems(payload) {
    if (payload.data) {
      if (payload.data?.keys && Array.isArray(payload.data.keys)) {
        return payload.data.keys.map((key) => {
          const keyInfo = payload.data.key_info?.[key] || {};
          return {
            serial_number: key,
            ...keyInfo,
          };
        });
      }
      Object.assign(payload, payload.data);
      delete payload.data;
    }

    return payload;
  }
}
