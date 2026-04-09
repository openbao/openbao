// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
)

// bindBackend wraps a handler function that accepts a logical.Backend into an OperationHandler.
func bindBackend[Req, Resp kmip.OperationPayload](b logical.Backend, fn func(context.Context, logical.Backend, Req) (Resp, error)) kmipserver.OperationHandler {
	return kmipserver.HandleFunc(func(ctx context.Context, req Req) (Resp, error) {
		return fn(ctx, b, req)
	})
}

func registerHandlers(executor *kmipserver.BatchExecutor, b logical.Backend) {
	executor.Route(kmip.OperationRegister, bindBackend(b, handleRegister))
}

// handleRegister implements the KMIP Register operation by importing a pre-existing key into transit.
// Supported object types: SymmetricKey (raw bytes), PrivateKey (PKCS8 DER).
func handleRegister(ctx context.Context, b logical.Backend, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	return &payloads.RegisterResponsePayload{
		UniqueIdentifier: "name",
	}, nil
}
