// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault"
)

func handleSysHealth(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if core.HasActiveContext() {
			handleLogicalNoForward(core).ServeHTTP(w, r)
			return
		}

		switch r.Method {
		case "GET":
			handleSysHealthGet(core, w, r)
		case "HEAD":
			handleSysHealthHead(core, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
		}
	})
}

func handleSysHealthGet(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	code, body, err := getSysHealth(core, r)
	if err != nil {
		core.Logger().Error("error checking health", "error", err)
		respondError(w, code, nil)
		return
	}

	if body == nil {
		respondError(w, code, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	// Generate the response
	enc := json.NewEncoder(w)
	enc.Encode(body)
}

func handleSysHealthHead(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	code, body, _ := getSysHealth(core, r)

	if body != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(code)
}

func getSysHealth(core *vault.Core, r *http.Request) (int, *vault.HealthResponse, error) {
	fd := &framework.FieldData{
		Raw:    parseQuery(r.URL.Query()),
		Schema: vault.SysHealthSchema,
	}

	err := fd.Validate()
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	ctx := namespace.RootContext(r.Context())

	return core.GetSysHealth(ctx, fd, false, false)
}
