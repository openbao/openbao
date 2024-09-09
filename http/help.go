// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"errors"
	"net/http"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

func wrapHelpHandler(h http.Handler, core *vault.Core) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		// If the help parameter is not blank, then show the help. We request
		// forward because standby nodes do not have mounts and other state.
		if v := req.URL.Query().Get("help"); v != "" || req.Method == "HELP" {
			handleRequestForwarding(core,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handleHelp(core, w, r)
				})).ServeHTTP(writer, req)
			return
		}

		h.ServeHTTP(writer, req)
		return
	})
}

func handleHelp(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	ns, err := namespace.FromContext(r.Context())
	if err != nil {
		respondError(w, http.StatusBadRequest, nil)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		respondError(w, http.StatusNotFound, errors.New("Missing /v1/ prefix in path. Use vault path-help command to retrieve API help for paths"))
		return
	}
	path := ns.TrimmedPath(r.URL.Path[len("/v1/"):])

	req := &logical.Request{
		Operation:  logical.HelpOperation,
		Path:       path,
		Connection: getConnection(r),
	}
	requestAuth(r, req)

	resp, err := core.HandleRequest(r.Context(), req)
	if err != nil {
		respondErrorCommon(w, req, resp, err)
		return
	}

	respondOk(w, resp.Data)
}
