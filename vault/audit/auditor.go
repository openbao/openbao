// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
package audit

import (
	"context"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type AuditLogger interface {
	AuditRequest(ctx context.Context, input *logical.LogInput) error
	AuditResponse(ctx context.Context, input *logical.LogInput) error
}

type BasicAuditor struct {
	broker *Broker
}

func NewBasicAuditor(b *Broker) BasicAuditor {
	return BasicAuditor{broker: b}
}

func (b BasicAuditor) AuditRequest(ctx context.Context, input *logical.LogInput) error {
	return b.broker.LogRequest(ctx, input)
}

func (b BasicAuditor) AuditResponse(ctx context.Context, input *logical.LogInput) error {
	return b.broker.LogResponse(ctx, input)
}

type GenericAuditor struct {
	broker    *Broker
	mountType string
	namespace *namespace.Namespace
}

func NewGenericAuditor(b *Broker, mt string, ns *namespace.Namespace) GenericAuditor {
	return GenericAuditor{broker: b, mountType: mt, namespace: ns}
}

func (g GenericAuditor) AuditRequest(ctx context.Context, input *logical.LogInput) error {
	ctx = namespace.ContextWithNamespace(ctx, g.namespace)
	logInput := *input
	logInput.Type = g.mountType + "-request"
	return g.broker.LogRequest(ctx, &logInput)
}

func (g GenericAuditor) AuditResponse(ctx context.Context, input *logical.LogInput) error {
	ctx = namespace.ContextWithNamespace(ctx, g.namespace)
	logInput := *input
	logInput.Type = g.mountType + "-response"
	return g.broker.LogResponse(ctx, &logInput)
}
