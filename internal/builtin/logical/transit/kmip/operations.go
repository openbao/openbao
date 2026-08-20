// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"slices"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
)

var SupportedOperations = []kmiplib.Operation{
	kmiplib.OperationRegister,
	kmiplib.OperationCreate,
	kmiplib.OperationGet,
	kmiplib.OperationGetAttributes,
	kmiplib.OperationLocate,
	kmiplib.OperationActivate,
	kmiplib.OperationRevoke,
	kmiplib.OperationDestroy,
	kmiplib.OperationEncrypt,
	kmiplib.OperationDecrypt,
	kmiplib.OperationSign,
	kmiplib.OperationSignatureVerify,
	kmiplib.OperationQuery,
}

var SupportedObjectTypes = []kmiplib.ObjectType{
	kmiplib.ObjectTypeSymmetricKey,
	kmiplib.ObjectTypePrivateKey,
	kmiplib.ObjectTypePublicKey,
}

func ValidOperations() []string {
	names := make([]string, len(SupportedOperations))
	for i, op := range SupportedOperations {
		names[i] = ttlv.EnumStr(op)
	}
	slices.Sort(names)
	return names
}

func IsValidOperation(name string) bool {
	return slices.Contains(ValidOperations(), name)
}
