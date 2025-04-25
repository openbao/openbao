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
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/vault"
	"github.com/openbao/openbao/vault/quotas"
)

var (
	restrictedAPIs = []string{
		"sys/audit",
		"sys/audit-hash",
		"sys/config/auditing",
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
		"sys/internal/inspect/router",
		"sys/key-status",
		"sys/loggers",
		"sys/managed-keys",
		"sys/metrics",
		"sys/mfa/method",
		"sys/monitor",
		"sys/pprof",
		"sys/quotas/config",
		"sys/quotas/lease-count",
		"sys/quotas/rate-limit",
		"sys/raw",
		"sys/rekey",
		"sys/rekey-recovery-key",
		"sys/replication/merkle-check",
		"sys/replication/recover",
		"sys/replication/reindex",
		"sys/replication/status",
		"sys/rotate",
		"sys/rotate/config",
		"sys/seal",
		"sys/sealwrap/rewrap",
		"sys/step-down",
		"sys/storage",
		"sys/sync/config",
		"sys/unseal",
	}

	resolveNamespace = func(core *vault.Core, r *http.Request) (*namespace.Namespace, int, error) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			// Default namespace for all requests that don't go to /v1.
			return namespace.RootNamespace, 0, nil
		}

		nsHeader := r.Header.Get(consts.NamespaceHeaderName)
		ns, trimmedPath, err := core.ResolveNamespaceFromRequest(nsHeader, strings.TrimPrefix(r.URL.Path, "/v1/"))
		if err != nil {
			return nil, http.StatusNotFound, err
		}

		r.URL.Path = "/v1/" + ns.Path + trimmedPath

		// No need to check for restricted APIs, return early.
		if ns.ID == namespace.RootNamespaceID {
			return ns, 0, nil
		}

		for _, api := range restrictedAPIs {
			// Either:
			// - Direct match with no '/' at end of path
			// - Path starts with restricted API, final '/' or further path components afterwards
			if trimmedPath == api || (strings.HasPrefix(trimmedPath, api) && trimmedPath[len(api)] == '/') {
				return ns, http.StatusBadRequest, fmt.Errorf("unavailable operation (%s %s)", r.Method, r.URL.Path)
			}
		}

		return ns, 0, nil
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
