// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"errors"
	"slices"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

var ErrNoRole = errors.New("no matching role for certificate")

type ctxKmipPermissions struct{}

type permissions struct {
	allowedOps  []string
	allowedKeys []string
}

// authMeddleware authenticates every KMIP request by callind a.AuthenticateCert and enrich context with permissions.
func authMiddleware(a Adapter) kmipserver.Middleware {
	return func(next kmipserver.Next, ctx context.Context, msg *kmiplib.RequestMessage) (*kmiplib.ResponseMessage, error) {
		certs := kmipserver.PeerCertificates(ctx)
		if len(certs) == 0 {
			return nil, kmipserver.Errorf(kmiplib.ResultReasonPermissionDenied, "client certificate not provided")
		}

		subjectDN := certs[0].Subject.String()

		allowedOps, allowedKeys, err := a.AuthenticateCert(ctx, subjectDN)
		if err != nil {
			if errors.Is(err, ErrNoRole) {
				return nil, kmipserver.Errorf(kmiplib.ResultReasonPermissionDenied, "no matching role for certificate subject %q", subjectDN)
			}
			return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "failed to lookup role: %s", err)
		}

		ctx = context.WithValue(ctx, ctxKmipPermissions{}, &permissions{
			allowedOps:  allowedOps,
			allowedKeys: allowedKeys,
		})

		return next(ctx, msg)
	}
}

// authOp checks allowed operations and keys for the authenticated client.
func authOp(ctx context.Context, op kmiplib.Operation, keyName string) error {
	p, _ := ctx.Value(ctxKmipPermissions{}).(*permissions)
	if p == nil {
		return kmipserver.ErrPermissionDenied
	}

	if len(p.allowedOps) > 0 {
		opStr := ttlv.EnumStr(op)
		if !slices.Contains(p.allowedOps, opStr) {
			return kmipserver.Errorf(kmiplib.ResultReasonPermissionDenied, "operation %s is not allowed", opStr)
		}
	}

	if keyName != "" && len(p.allowedKeys) > 0 {
		if !slices.Contains(p.allowedKeys, keyName) {
			return kmipserver.Errorf(kmiplib.ResultReasonPermissionDenied, "key %q is not allowed", keyName)
		}
	}

	return nil
}
