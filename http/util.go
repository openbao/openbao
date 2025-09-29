// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/helper/buffer"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/openbao/openbao/vault"
	"github.com/openbao/openbao/vault/quotas"
)

var (
	genericWrapping = func(core *vault.Core, in http.Handler, props *vault.HandlerProperties) http.Handler {
		// Wrap the help wrapped handler with another layer with a generic
		// handler
		return wrapGenericHandler(core, in, props)
	}

	additionalRoutes = func(mux *http.ServeMux, core *vault.Core) {}

	nonVotersAllowed = true

	adjustResponse = func(core *vault.Core, w http.ResponseWriter, req *logical.Request) {}
)

func resetBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	seekable, ok := req.Body.(io.Seeker)
	if !ok {
		return fmt.Errorf("unable to seek body: wrong type")
	}

	if _, err := seekable.Seek(0, io.SeekStart); err != nil {
		return err
	}

	return nil
}

func wrapMaxRequestSizeHandler(handler http.Handler, props *vault.HandlerProperties) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var maxRequestSize int64
		if props.ListenerConfig != nil {
			maxRequestSize = props.ListenerConfig.MaxRequestSize
		}
		if maxRequestSize == 0 {
			maxRequestSize = DefaultMaxRequestSize
		}

		// Before continuing, clone the request: per https://pkg.go.dev/net/http#Handler,
		//
		// > Except for reading the body, handlers should not modify the
		// > provided Request.
		//
		// As we're intentionally mutating the body (and not simply reading
		// it), clone it first.
		ctx := r.Context()
		clonedReq := r.Clone(ctx)

		originalBody := clonedReq.Body
		if maxRequestSize > 0 {
			clonedReq.Body = http.MaxBytesReader(w, clonedReq.Body, maxRequestSize)
		}

		ctx = logical.CreateContextOriginalBody(ctx, originalBody)
		clonedReq = clonedReq.WithContext(ctx)

		// Now that we've size-limited the body, copy it into a buffer: we
		// need this so that we can:
		//
		// 1. Read the role for login requests with a role-specific rate-limit
		//    quota.
		// 2. Tell the difference between JSON and Form requests when the
		//    Content-Type is form (to allow legacy behavior).
		// 3. For enforcing JSON resource limits.
		// 4. For request forwarding, to send the original body along with
		//    the request.
		//
		// While theoretically this could delay processing of the body, in
		// reality the above already enforces that: json.Unmarshal(...) in
		// either code path will stall until all data is available, though
		// memory access patterns might be different. We trust r.Body to
		// throw an IO error on context cancellation and we've already
		// enforced maximum limits.
		var err error
		clonedReq.Body, err = buffer.NewSeekableReader(clonedReq.Body)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}

		// Subsequent handlers can now type assert to *seekableReader and
		// be able to seek back to beginning.
		handler.ServeHTTP(w, clonedReq)
	})
}

func rateLimitQuotaWrapping(handler http.Handler, core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			handler.ServeHTTP(w, r)
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

		// NOTE: The namespace and mount resolved here may differ from the ones
		// later resolved in core and used for the remainder of request handling.
		// For example, this can happen if there is a seal->unseal transition
		// between this point in request handling and once we read-lock core's state.
		// The worst-case outcome is that we don't know of a potential quota
		// configuration at this point (because core is sealed) and let the request
		// bypass rate limiting right into core if it has queued up right before the
		// unseal process begins.
		nsHeader := namespace.HeaderFromContext(r.Context())
		ns, trimmedPath := core.ResolveNamespaceFromRequest(nsHeader, path)
		if ns == nil {
			ns = namespace.RootNamespace
		}
		ctx := namespace.ContextWithNamespace(r.Context(), ns)
		mountPath := strings.TrimPrefix(core.MatchingMount(ctx, trimmedPath), ns.Path)

		quotaReq := &quotas.Request{
			Type:          quotas.TypeRateLimit,
			Path:          path,
			MountPath:     mountPath,
			NamespacePath: ns.Path,
			ClientAddress: parseRemoteIPAddress(r),
		}

		// This checks if any role based quota is required (LCQ or RLQ).
		requiresResolveRole, err := core.ResolveRoleForQuotas(quotaReq)
		if err != nil {
			core.Logger().Error("failed to lookup quotas", "path", path, "error", err)
			respondError(w, http.StatusInternalServerError, err)
			return
		}

		// If any role-based quotas are enabled for this namespace/mount, just
		// do the role resolution once here.
		if requiresResolveRole {
			role := core.DetermineRoleFromLoginRequestFromReader(ctx, mountPath, r.Body)

			// Reset our body to the beginning.
			if err := resetBody(r); err != nil {
				respondError(w, http.StatusInternalServerError, err)
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
				req, status, err := buildLogicalRequestNoAuth(w, r)
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
