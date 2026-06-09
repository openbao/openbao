// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"errors"

	kmiplib "github.com/ovh/kmip-go"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/ovh/kmip-go/kmipserver"
)

func mapError(err error) error {
	if err == nil {
		return nil
	}

	var kmipErr *kmipserver.Error
	if errors.As(err, &kmipErr) {
		return err
	}

	// ToDo: not found / already exists / invalied field etc...
	switch {
	case errors.Is(err, logical.ErrPermissionDenied):
		return kmipserver.Errorf(kmiplib.ResultReasonPermissionDenied, "%s", err.Error())
	case errors.Is(err, logical.ErrUnsupportedOperation):
		return kmipserver.Errorf(kmiplib.ResultReasonOperationNotSupported, "%s", err.Error())
	default:
		return kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "%s", err.Error())
	}
}
