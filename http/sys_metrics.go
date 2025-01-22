// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"errors"
	"net/http"

	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

func handleMetricsUnauthenticated(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := &logical.Request{Headers: r.Header}

		switch r.Method {
		case "GET":
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
			return
		}

		// Parse form
		if err := r.ParseForm(); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}

		format := r.Form.Get("format")
		if format == "" {
			format = metricsutil.FormatFromRequest(req)
		}

		// Define response
		resp := core.MetricsHelper().ResponseForFormat(format)

		// Manually extract the logical response and send back the information
		status := resp.Data[logical.HTTPStatusCode].(int)
		w.Header().Set("Content-Type", resp.Data[logical.HTTPContentType].(string))
		switch v := resp.Data[logical.HTTPRawBody].(type) {
		case string:
			w.WriteHeader(status)
			w.Write([]byte(v))
		case []byte:
			w.WriteHeader(status)
			w.Write(v)
		default:
			respondError(w, http.StatusInternalServerError, errors.New("wrong response returned"))
		}
	})
}
