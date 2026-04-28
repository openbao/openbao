// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	log "github.com/hashicorp/go-hclog"
	metrics "github.com/hashicorp/go-metrics/compat"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
)

type backendEntry struct {
	backend audit.Backend
	view    barrier.View
	local   bool
}

// Broker is used to provide a single ingest interface to auditable
// events given that multiple backends may be configured.
type Broker struct {
	sync.RWMutex
	backends map[string]backendEntry
	// auditedHeadersConfig is used to configure which http headers
	// can be rendered in the audit logs.
	auditedHeadersConfig *AuditedHeadersConfig
	logger               log.Logger
}

// NewAuditBroker creates a new audit broker.
func NewAuditBroker(ctx context.Context, view barrier.View, log log.Logger) (*Broker, error) {
	ahc, err := newAuditedHeadersConfig(ctx, view)
	if err != nil {
		return nil, err
	}

	return &Broker{
		backends:             make(map[string]backendEntry),
		auditedHeadersConfig: ahc,
		logger:               log,
	}, nil
}

func (b *Broker) AuditedHeaderConfig() *AuditedHeadersConfig {
	return b.auditedHeadersConfig
}

// Register is used to add new audit backend to the broker
func (b *Broker) Register(name string, backend audit.Backend, v barrier.View, local bool) {
	b.Lock()
	defer b.Unlock()
	b.backends[name] = backendEntry{
		backend: backend,
		view:    v,
		local:   local,
	}
}

// Deregister is used to remove an audit backend from the broker
func (b *Broker) Deregister(name string) {
	b.Lock()
	defer b.Unlock()
	delete(b.backends, name)
}

// IsRegistered is used to check if a given audit backend is registered
func (b *Broker) IsRegistered(name string) bool {
	b.RLock()
	defer b.RUnlock()
	_, ok := b.backends[name]
	return ok
}

// Count returns the number of registered backends
func (b *Broker) Count() int {
	b.RLock()
	defer b.RUnlock()
	return len(b.backends)
}

// IsLocal is used to check if a given audit backend is registered
func (b *Broker) IsLocal(name string) (bool, error) {
	b.RLock()
	defer b.RUnlock()
	be, ok := b.backends[name]
	if ok {
		return be.local, nil
	}
	return false, fmt.Errorf("unknown audit backend %q", name)
}

// GetHash returns a hash using the salt of the given backend
func (b *Broker) GetHash(ctx context.Context, name string, input string) (string, error) {
	b.RLock()
	defer b.RUnlock()
	be, ok := b.backends[name]
	if !ok {
		return "", fmt.Errorf("unknown audit backend %q", name)
	}

	return be.backend.GetHash(ctx, input)
}

// LogRequest is used to ensure all the audit backends have an opportunity to
// log the given request and that *at least one* succeeds.
func (b *Broker) LogRequest(ctx context.Context, in *logical.LogInput) (ret error) {
	defer metrics.MeasureSince([]string{"audit", "log_request"}, time.Now())
	b.RLock()
	defer b.RUnlock()
	if in.Request.InboundSSCToken != "" {
		if in.Auth != nil {
			reqAuthToken := in.Auth.ClientToken
			in.Auth.ClientToken = in.Request.InboundSSCToken
			defer func() {
				in.Auth.ClientToken = reqAuthToken
			}()
		}
	}

	var retErr *multierror.Error

	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("panic during logging", "request_path", in.Request.Path, "error", r, "stacktrace", string(debug.Stack()))
			retErr = multierror.Append(retErr, errors.New("panic generating audit log"))
		}

		ret = retErr.ErrorOrNil()
		failure := float32(0.0)
		if ret != nil {
			failure = 1.0
		}
		metrics.IncrCounter([]string{"audit", "log_request_failure"}, failure)
	}()

	// All logged requests must have an identifier
	//if req.ID == "" {
	//	a.logger.Error("missing identifier in request object", "request_path", req.Path)
	//	retErr = multierror.Append(retErr, fmt.Errorf("missing identifier in request object: %s", req.Path))
	//	return
	//}

	headers := in.Request.Headers
	defer func() {
		in.Request.Headers = headers
	}()

	// Ensure at least one backend logs
	anyLogged := false
	for name, be := range b.backends {
		in.Request.Headers = nil
		transHeaders, thErr := b.auditedHeadersConfig.Apply(ctx, headers, be.backend.GetHash)
		if thErr != nil {
			b.logger.Error("backend failed to include headers", "backend", name, "error", thErr)
			continue
		}
		in.Request.Headers = transHeaders

		start := time.Now()
		lrErr := be.backend.LogRequest(ctx, in)
		metrics.MeasureSince([]string{"audit", name, "log_request"}, start)
		if lrErr != nil {
			b.logger.Error("backend failed to log request", "backend", name, "error", lrErr)
		} else {
			anyLogged = true
		}
	}
	if !anyLogged && len(b.backends) > 0 {
		retErr = multierror.Append(retErr, errors.New("no audit backend succeeded in logging the request"))
	}

	return retErr.ErrorOrNil()
}

// LogResponse is used to ensure all the audit backends have an opportunity to
// log the given response and that *at least one* succeeds.
func (b *Broker) LogResponse(ctx context.Context, in *logical.LogInput) (ret error) {
	defer metrics.MeasureSince([]string{"audit", "log_response"}, time.Now())
	b.RLock()
	defer b.RUnlock()
	if in.Request.InboundSSCToken != "" {
		if in.Auth != nil {
			reqAuthToken := in.Auth.ClientToken
			in.Auth.ClientToken = in.Request.InboundSSCToken
			defer func() {
				in.Auth.ClientToken = reqAuthToken
			}()
		}
	}

	var retErr *multierror.Error

	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("panic during logging", "request_path", in.Request.Path, "error", r, "stacktrace", string(debug.Stack()))
			retErr = multierror.Append(retErr, errors.New("panic generating audit log"))
		}

		ret = retErr.ErrorOrNil()

		failure := float32(0.0)
		if ret != nil {
			failure = 1.0
		}
		metrics.IncrCounter([]string{"audit", "log_response_failure"}, failure)
	}()

	headers := in.Request.Headers
	defer func() {
		in.Request.Headers = headers
	}()

	// Ensure at least one backend logs
	anyLogged := false
	for name, be := range b.backends {
		in.Request.Headers = nil
		transHeaders, thErr := b.auditedHeadersConfig.Apply(ctx, headers, be.backend.GetHash)
		if thErr != nil {
			b.logger.Error("backend failed to include headers", "backend", name, "error", thErr)
			continue
		}
		in.Request.Headers = transHeaders

		start := time.Now()
		lrErr := be.backend.LogResponse(ctx, in)
		metrics.MeasureSince([]string{"audit", name, "log_response"}, start)
		if lrErr != nil {
			b.logger.Error("backend failed to log response", "backend", name, "error", lrErr)
		} else {
			anyLogged = true
		}
	}
	if !anyLogged && len(b.backends) > 0 {
		retErr = multierror.Append(retErr, errors.New("no audit backend succeeded in logging the response"))
	}

	return retErr.ErrorOrNil()
}

func (b *Broker) Invalidate(ctx context.Context, key string) {
	// For now we ignore the key as this would only apply to salts. We just
	// sort of brute force it on each one.
	b.Lock()
	defer b.Unlock()
	for _, be := range b.backends {
		be.backend.Invalidate(ctx)
	}
}
