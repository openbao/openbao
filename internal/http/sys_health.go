// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/openbao/openbao/v2/internal/version"
)

func handleSysHealth(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	code, body, err := getSysHealthRaw(core, r)
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
	code, body, _ := getSysHealthRaw(core, r)

	if body != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(code)
}

func getSysHealthRaw(core *vault.Core, r *http.Request) (int, *HealthResponse, error) {
	fd := &framework.FieldData{
		Raw:    parseQuery(r.URL.Query()),
		Schema: vault.SysHealthSchema,
	}

	err := fd.Validate()
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	ctx := namespace.RootContext(r.Context())

	return getSysHealth(ctx, core, fd)
}

func getSysHealth(ctx context.Context, core *vault.Core, fd *framework.FieldData) (int, *HealthResponse, error) {
	var err error

	// Check system status
	sealed := core.Sealed()
	standby := core.Standby()
	var replicationState consts.ReplicationState
	if standby {
		replicationState = core.ActiveNodeReplicationState()
	} else {
		replicationState = core.ReplicationState()
	}

	init, err := core.Initialized(ctx)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}

	// Determine the status code
	code := fd.Get("activecode").(int)
	switch {
	case !init:
		code = fd.Get("uninitcode").(int)
	case sealed:
		code = fd.Get("sealedcode").(int)
	case standby:
		// Check if being a standby is allowed for the purpose of a 200 OK
		standbyOK := fd.Get("standbyok").(bool)
		if !standbyOK {
			code = fd.Get("standbycode").(int)
		}
	}

	hr := &HealthResponse{
		Initialized:                init,
		Sealed:                     sealed,
		Standby:                    standby,
		ReplicationPerformanceMode: replicationState.GetPerformanceString(),
		ReplicationDRMode:          replicationState.GetDRString(),
		ServerTimeUTC:              time.Now().UTC().Unix(),
		Version:                    version.GetVersion().VersionNumber(),
	}

	// Fetch the local cluster name and identifier
	if !sealed {
		cluster, err := core.Cluster(ctx)
		if err != nil {
			return http.StatusInternalServerError, nil, err
		}

		hr.ClusterName = cluster.Name
		hr.ClusterID = cluster.ID
	}

	return code, hr, nil
}

type HealthResponse struct {
	Initialized                bool   `json:"initialized"`
	Sealed                     bool   `json:"sealed"`
	Standby                    bool   `json:"standby"`
	ReplicationPerformanceMode string `json:"replication_performance_mode"`
	ReplicationDRMode          string `json:"replication_dr_mode"`
	ServerTimeUTC              int64  `json:"server_time_utc"`
	Version                    string `json:"version"`
	ClusterName                string `json:"cluster_name,omitempty"`
	ClusterID                  string `json:"cluster_id,omitempty"`
}
