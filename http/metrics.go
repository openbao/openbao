// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"net/http"

	"github.com/openbao/openbao/vault"
)

// wrapMetricsListenerHandler is an HTTP middleware that enforces listener-specific
// metrics access rules. It checks for DisallowMetrics and MetricsOnly options
// in the listener's configuration and blocks requests accordingly.
func wrapMetricsListenerHandler(handler http.Handler, props *vault.HandlerProperties) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No listener-specific configuration to apply.
		if props.ListenerConfig == nil {
			handler.ServeHTTP(w, r)
			return
		}

		listenerConfig := props.ListenerConfig

		isMetricsOnly := listenerConfig.Telemetry.MetricsOnly
		disallowsMetrics := listenerConfig.Telemetry.DisallowMetrics

		realMetricsPath := "/v1/sys/metrics"
		metricsPath := realMetricsPath

		if isMetricsOnly && props.ListenerConfig.Telemetry.MetricsPath != "" {
			metricsPath = props.ListenerConfig.Telemetry.MetricsPath
		}

		isMetricsPath := r.URL.Path == metricsPath

		// Block requests to the metrics endpoint if the listener is configured to disallow it.
		// This rule has the highest precedence.
		if disallowsMetrics && isMetricsPath {
			http.Error(w, "metrics endpoint is disabled for this listener", http.StatusForbidden)
			return
		}

		// If the listener is configured for metrics only, block all other paths.
		if isMetricsOnly && !isMetricsPath {
			http.Error(w, "this listener only serves the metrics endpoint", http.StatusNotFound)
			return
		}

		// Lastly, if it is a metrics request and we've chosen a custom path
		// to respond to metrics on, revert to the standard path.
		if isMetricsPath && metricsPath != realMetricsPath {
			r.URL.Path = realMetricsPath
			r.URL.RawPath = realMetricsPath
		}

		// The request is permitted; pass it to the next handler in the chain.
		handler.ServeHTTP(w, r)
	})
}
