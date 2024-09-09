// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"encoding/json"
	"net/http"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/vault"
)

type FeatureFlagsResponse struct {
	FeatureFlags []string `json:"feature_flags"`
}

var FeatureFlag_EnvVariables = [...]string{
	"BAO_CLOUD_ADMIN_NAMESPACE",
}

func featureFlagIsSet(name string) bool {
	switch api.ReadBaoVariable(name) {
	case "", "0":
		return false
	default:
		return true
	}
}

func handleSysInternalFeatureFlags(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			break
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
		}

		response := &FeatureFlagsResponse{}

		for _, f := range FeatureFlag_EnvVariables {
			if featureFlagIsSet(f) {
				response.FeatureFlags = append(response.FeatureFlags, f)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Generate the response
		enc := json.NewEncoder(w)
		enc.Encode(response)
	})
}
