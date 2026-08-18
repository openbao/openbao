// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/sethvargo/go-limiter/httplimit"
)

// addLatestStorageIndex sets the X-Vault-Index header on the response.
//
// In the future, this may need to be made namespace aware, perhaps through
// adding the namespace accessor (of the namespace with its own storage
// backend) to the cluster ID as a suffix.
func addLatestStorageIndex(core *vault.Core, ctx context.Context, w http.ResponseWriter) {
	cluster := core.ClusterID()
	if cluster == "" {
		return
	}

	if index := core.MaybeGetLatestStorageIndex(ctx); index != "" {
		value := fmt.Sprintf("%v:%v", cluster, index)
		w.Header().Add(api.IndexHeaderName, value)
	}
}

// wrapIndexForwardHandler wraps the given HTTP handler for the core to
// process index headers (X-Vault-Index and X-Vault-Inconsistent).
func wrapIndexForwardHandler(mux http.Handler, core *vault.Core, props *vault.HandlerProperties) http.Handler {
	cfg := props.ListenerConfig
	if cfg == nil {
		cfg = &configutil.Listener{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse header values.
		index, consistencyBehaviors, ok := getAndValidateIndexHeaders(core, w, r, cfg.ConsistencyFallbackBehavior)
		if !ok {
			return
		}

		if index == "" || !core.Standby() {
			handleWithoutIndexForward(mux, core, w, r, consistencyBehaviors, cfg.ConsistencyMissingHeaderForward)
			return
		}

		// Now apply the default consistency behavior of `fail`.
		if len(consistencyBehaviors) == 0 {
			consistencyBehaviors = []string{api.IndexInconsistentFail}
		}

		await := consistencyBehaviors[0] == api.IndexInconsistentAwait
		forward := consistencyBehaviors[0] == api.IndexInconsistentForward || (len(consistencyBehaviors) == 2 && consistencyBehaviors[1] == api.IndexInconsistentForward)

		handleIndexForward(mux, core, w, r, index, await, forward, cfg.ConsistencyMaxIndexWait)
	})
}

func getAndValidateIndexHeaders(core *vault.Core, w http.ResponseWriter, r *http.Request, fallback string) (string, []string, bool) {
	if fallback == "" {
		fallback = api.IndexInconsistentFail
	}

	var index string
	indices := r.Header.Values(api.IndexHeaderName)
	if len(indices) > 1 {
		respondError(w, http.StatusBadRequest, fmt.Errorf("expected at most one value for %q", api.IndexHeaderName))
		return "", nil, false
	} else if len(indices) == 1 {
		index = indices[0]
	}

	cluster := core.ClusterID()
	index, ok := strings.CutPrefix(index, cluster+":")
	if !ok {
		// Treat index values meant for other cluster as missing.
		index = ""
	}

	values := r.Header.Values(api.IndexInconsistentHeaderName)
	if len(values) > 2 {
		respondError(w, http.StatusBadRequest, fmt.Errorf("expected at most two values for %q", api.IndexInconsistentHeaderName))
		return "", nil, false
	}

	switch {
	case len(values) == 0:
	case values[0] == api.IndexInconsistentFail || values[0] == api.IndexInconsistentForward:
		if len(values) > 1 {
			respondError(w, http.StatusBadRequest, fmt.Errorf("%v=%v cannot be used with more than one value", api.IndexInconsistentHeaderName, values[0]))
			return "", nil, false
		}
	case values[0] == api.IndexInconsistentAwait:
		// If we don't have a second value, take the value from configuration.
		if len(values) == 1 {
			values = append(values, fallback)
		}

		switch values[1] {
		case api.IndexInconsistentFail, api.IndexInconsistentForward:
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf("unknown second value for %q: must either be %q or %q", api.IndexInconsistentHeaderName, api.IndexInconsistentFail, api.IndexInconsistentForward))
			return "", nil, false
		}
	default:
		respondError(w, http.StatusBadRequest, fmt.Errorf("unknown value for %q header", api.IndexInconsistentHeaderName))
		return "", nil, false
	}

	return index, values, true
}

func handleWithoutIndexForward(mux http.Handler, core *vault.Core, w http.ResponseWriter, r *http.Request, inconsistent []string, forward bool) {
	// When no index header is present but the caller set X-Vault-Inconsistent,
	// it is aware of forwarding behaviors but just doesn't have an index it
	// wants to set or is aware of. Similarly, if configuration states to
	// handle locally or we're the active node, do so as well.
	//
	// It doesn't really matter what the inconsistent header value is, here.
	if !forward || len(inconsistent) > 0 || !core.Standby() {
		mux.ServeHTTP(w, r)
		return
	}

	// Here, we know:
	//
	// 1. We have a missing X-Vault-Inconsistent value, so we assume we're on
	//    a client that's not aware of inconsistency headers.
	// 2. Our default configuration option is to forward the request to the
	//    active.
	// 3. We're not the active.
	//
	// So forward it.
	forwardRequest(core, w, r)
}

func handleIndexForward(mux http.Handler, core *vault.Core, w http.ResponseWriter, r *http.Request, index string, await bool, forward bool, maxWait time.Duration) {
	if await {
		handleIndexForwardWithAwait(mux, core, w, r, index, forward, maxWait)
		return
	}

	seen, err := core.HaveSeenStorageIndex(r.Context(), index)
	if err != nil {
		// Treat errors as seen indices: this ensures most distributed load
		// across the cluster if the system is down.
		seen = true
	}

	handleIndexForwardResults(mux, core, w, r, seen, forward)
}

func handleIndexForwardWithAwait(mux http.Handler, core *vault.Core, w http.ResponseWriter, r *http.Request, index string, forward bool, maxWait time.Duration) {
	// the maximum server side wait context. This lets us forward
	// the request sooner if we encounter timeouts.
	ctx, cancel := context.WithTimeout(r.Context(), maxWait+100*time.Millisecond)
	defer cancel()

	seen := core.AwaitStorageIndex(ctx, index)
	handleIndexForwardResults(mux, core, w, r, seen, forward)
}

func handleIndexForwardResults(mux http.Handler, core *vault.Core, w http.ResponseWriter, r *http.Request, seen bool, forward bool) {
	if seen {
		// We reached the desired index state; handle it locally.
		mux.ServeHTTP(w, r)
		return
	}

	if forward {
		// Forward the request to the active node; the state hasn't yet been seen.
		forwardRequest(core, w, r)
		return
	}

	// Tell the client to retry later; the state hasn't yet been seen.
	w.Header().Add(httplimit.HeaderRetryAfter, "1")
	respondError(w, http.StatusTooManyRequests, nil)
}
