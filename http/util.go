// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault"
	"github.com/openbao/openbao/vault/quotas"
)

var (
	restrictedAPIs = []string{
		"sys/audit",
		"sys/audit-hash",
		"sys/config/cors",
		"sys/config/reload",
		"sys/config/state",
		"sys/config/ui",
		"sys/decode-token",
		"sys/generate-recovery-token",
		"sys/generate-root",
		"sys/health",
		"sys/host-info",
		"sys/in-flight-req",
		"sys/init",
		"sys/internal/counters/activity",
		"sys/internal/counters/activity/export",
		"sys/internal/counters/activity/monthly",
		"sys/internal/counters/config",
		"sys/key-status",
		"sys/loggers",
		"sys/metrics",
		"sys/monitor",
		"sys/quotas/config",
		"sys/quotas/lease-count",
		"sys/quotas/rate-limit",
		"sys/raw",
		"sys/rekey-recovery-key",
		"sys/replication/recover",
		"sys/replication/reindex",
		"sys/replication/status",
		"sys/replication/merkle-check",
		"sys/rotate/config",
		"sys/rotate",
		"sys/seal",
		"sys/sealwrap/rewrap",
		"sys/step-down",
		"sys/storage",
		"sys/sync/config",
		"sys/unseal",
	}
	containsAPIs = []string{
		"sys/config/auditing/",
		"sys/internal/inspect/router/",
		"sys/managed-keys/",
		"sys/mfa/method/",
		"sys/pprof/",
		"sys/rekey/",
	}

	validateNamespace = func(r *http.Request) int {
		ns, err := namespace.FromContext(r.Context())
		if err != nil {
			return http.StatusBadRequest
		}

		fullURL, err := url.JoinPath(ns.Path, r.URL.Path[4:])
		if err != nil {
			return http.StatusBadRequest
		}

		for _, api := range restrictedAPIs {
			apiSysRawRouted := "sys/raw/" + api
			// if path not equals the restricted api path or not equals restricted api path with "sys/raw/" prefix
			namespaceUseOfRestrictedEndpoint := (fullURL != api && fullURL != apiSysRawRouted) && strings.HasSuffix(fullURL, api)
			namespacePath, _, ok := strings.Cut(fullURL, api)

			// exclude any occurences of possible restricted APIs paths when path dictates that the suffix is a policy name
			if ok && (strings.HasSuffix(namespacePath, "sys/policies/acl/") || strings.HasSuffix(namespacePath, "sys/policy/")) {
				return 0
			}

			if namespaceUseOfRestrictedEndpoint {
				return http.StatusBadRequest
			}
		}

		for _, api := range containsAPIs {
			if strings.Contains(fullURL, api) && !strings.HasPrefix(fullURL, api) {
				return http.StatusBadRequest
			}
		}

		return 0
	}

	genericWrapping = func(core *vault.Core, in http.Handler, props *vault.HandlerProperties) http.Handler {
		// Wrap the help wrapped handler with another layer with a generic
		// handler
		return wrapGenericHandler(core, in, props)
	}

	additionalRoutes = func(mux *http.ServeMux, core *vault.Core) {}

	nonVotersAllowed = true

	adjustResponse = func(core *vault.Core, w http.ResponseWriter, req *logical.Request) {}
)

func wrapMaxRequestSizeHandler(handler http.Handler, props *vault.HandlerProperties) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var maxRequestSize int64
		if props.ListenerConfig != nil {
			maxRequestSize = props.ListenerConfig.MaxRequestSize
		}
		if maxRequestSize == 0 {
			maxRequestSize = DefaultMaxRequestSize
		}
		ctx := r.Context()
		originalBody := r.Body
		if maxRequestSize > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
		}
		ctx = logical.CreateContextOriginalBody(ctx, originalBody)
		r = r.WithContext(ctx)

		handler.ServeHTTP(w, r)
	})
}

func rateLimitQuotaWrapping(handler http.Handler, core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns, err := namespace.FromContext(r.Context())
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}

		// We don't want to do buildLogicalRequestNoAuth here because, if the
		// request gets allowed by the quota, the same function will get called
		// again, which is not desired.
		path, status, err := buildLogicalPath(r)
		if err != nil || status != 0 {
			respondError(w, status, err)
			return
		}
		mountPath := strings.TrimPrefix(core.MatchingMount(r.Context(), path), ns.Path)

		quotaReq := &quotas.Request{
			Type:          quotas.TypeRateLimit,
			Path:          path,
			MountPath:     mountPath,
			NamespacePath: ns.Path,
			ClientAddress: parseRemoteIPAddress(r),
		}

		// This checks if any role based quota is required (LCQ or RLQ).
		requiresResolveRole, err := core.ResolveRoleForQuotas(r.Context(), quotaReq)
		if err != nil {
			core.Logger().Error("failed to lookup quotas", "path", path, "error", err)
			respondError(w, http.StatusInternalServerError, err)
			return
		}

		// If any role-based quotas are enabled for this namespace/mount, just
		// do the role resolution once here.
		if requiresResolveRole {
			buf := bytes.Buffer{}
			teeReader := io.TeeReader(r.Body, &buf)
			role := core.DetermineRoleFromLoginRequestFromReader(r.Context(), mountPath, teeReader)

			// Reset the body if it was read
			if buf.Len() > 0 {
				r.Body = io.NopCloser(&buf)
				originalBody, ok := logical.ContextOriginalBodyValue(r.Context())
				if ok {
					r = r.WithContext(logical.CreateContextOriginalBody(r.Context(), newMultiReaderCloser(&buf, originalBody)))
				}
			}
			// add an entry to the context to prevent recalculating request role unnecessarily
			r = r.WithContext(context.WithValue(r.Context(), logical.CtxKeyRequestRole{}, role))
			quotaReq.Role = role
		}

		quotaResp, err := core.ApplyRateLimitQuota(r.Context(), quotaReq)
		if err != nil {
			core.Logger().Error("failed to apply quota", "path", path, "error", err)
			respondError(w, http.StatusInternalServerError, err)
			return
		}

		if core.RateLimitResponseHeadersEnabled() {
			for h, v := range quotaResp.Headers {
				w.Header().Set(h, v)
			}
		}

		if !quotaResp.Allowed {
			quotaErr := fmt.Errorf("request path %q: %w", path, quotas.ErrRateLimitQuotaExceeded)
			respondError(w, http.StatusTooManyRequests, quotaErr)

			if core.Logger().IsTrace() {
				core.Logger().Trace("request rejected due to rate limit quota violation", "request_path", path)
			}

			if core.RateLimitAuditLoggingEnabled() {
				req, _, status, err := buildLogicalRequestNoAuth(w, r)
				if err != nil || status != 0 {
					respondError(w, status, err)
					return
				}

				err = core.AuditLogger().AuditRequest(r.Context(), &logical.LogInput{
					Request:  req,
					OuterErr: quotaErr,
				})
				if err != nil {
					core.Logger().Warn("failed to audit log request rejection caused by rate limit quota violation", "error", err)
				}
			}

			return
		}

		handler.ServeHTTP(w, r)
		return
	})
}

func parseRemoteIPAddress(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}

	return ip
}

type multiReaderCloser struct {
	readers []io.Reader
	io.Reader
}

func newMultiReaderCloser(readers ...io.Reader) *multiReaderCloser {
	return &multiReaderCloser{
		readers: readers,
		Reader:  io.MultiReader(readers...),
	}
}

func (m *multiReaderCloser) Close() error {
	var err error
	for _, r := range m.readers {
		if c, ok := r.(io.Closer); ok {
			err = multierror.Append(err, c.Close())
		}
	}
	return err
}
