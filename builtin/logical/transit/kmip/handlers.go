// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/ovh/kmip-go/ttlv"
)

// bindAdapter wraps a handler function that accepts an Adapter into an OperationHandler.
func bindAdapter[Req, Resp kmiplib.OperationPayload](
	a Adapter,
	fn func(context.Context, Adapter, Req) (Resp, error),
) kmipserver.OperationHandler {
	return kmipserver.HandleFunc(func(ctx context.Context, req Req) (Resp, error) {
		return fn(ctx, a, req)
	})
}

// bindCrypto wraps a handler function to bind crypto adapter
func bindCrypto[Req, Resp kmiplib.OperationPayload](
	c CryptoAdapter,
	fn func(context.Context, CryptoAdapter, Req) (Resp, error),
) kmipserver.OperationHandler {
	return kmipserver.HandleFunc(func(ctx context.Context, req Req) (Resp, error) {
		return fn(ctx, c, req)
	})
}

func registerHandlers(executor *kmipserver.BatchExecutor, a Adapter) {
	executor.Route(kmiplib.OperationRegister, bindAdapter(a, handleRegister))
	executor.Route(kmiplib.OperationCreate, bindAdapter(a, handleCreate))
	executor.Route(kmiplib.OperationGet, bindAdapter(a, handleGet))
	executor.Route(kmiplib.OperationGetAttributes, bindAdapter(a, handleGetAttributes))
	executor.Route(kmiplib.OperationLocate, bindAdapter(a, handleLocate))
	executor.Route(kmiplib.OperationActivate, bindAdapter(a, handleActivate))
	executor.Route(kmiplib.OperationRevoke, bindAdapter(a, handleRevoke))
	executor.Route(kmiplib.OperationDestroy, bindAdapter(a, handleDestroy))

	if cryptoA, ok := a.(CryptoAdapter); ok {
		executor.Route(kmiplib.OperationEncrypt, bindCrypto(cryptoA, handleEncrypt))
		executor.Route(kmiplib.OperationDecrypt, bindCrypto(cryptoA, handleDecrypt))
		executor.Route(kmiplib.OperationSign, bindCrypto(cryptoA, handleSign))
		executor.Route(kmiplib.OperationSignatureVerify, bindCrypto(cryptoA, handleVerify))
	}
}

// handleRegister implements the KMIP Register operation by importing a pre-existing key into transit.
// Supported object types: SymmetricKey (raw bytes), PrivateKey (PKCS8 DER).
func handleRegister(ctx context.Context, a Adapter, req *payloads.RegisterRequestPayload) (*payloads.RegisterResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationRegister); err != nil {
		return nil, err
	}

	if req.Object == nil || req.ObjectType == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Object and ObjectType are required for Register")
	}

	var keyBlock *kmiplib.KeyBlock
	switch req.ObjectType {
	case kmiplib.ObjectTypeSymmetricKey:
		keyBlock = &req.Object.(*kmiplib.SymmetricKey).KeyBlock
		if keyBlock.KeyFormatType != kmiplib.KeyFormatTypeRaw {
			return nil, kmipserver.Errorf(
				kmiplib.ResultReasonKeyFormatTypeNotSupported,
				"SymmetricKey must be Raw, got %s", ttlv.EnumStr(keyBlock.KeyFormatType),
			)
		}
	case kmiplib.ObjectTypePrivateKey:
		keyBlock = &req.Object.(*kmiplib.PrivateKey).KeyBlock
		if keyBlock.KeyFormatType != kmiplib.KeyFormatTypePKCS_8 {
			return nil, kmipserver.Errorf(
				kmiplib.ResultReasonKeyFormatTypeNotSupported,
				"PrivateKey must be PKCS#8 DER, got %s", ttlv.EnumStr(keyBlock.KeyFormatType),
			)
		}
	default:
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"Object type %s is not supported", ttlv.EnumStr(req.ObjectType),
		)
	}

	alg, bitlen := AlgAndBitLenFromTemplateAttribute(req.TemplateAttribute)
	if alg == 0 {
		alg = keyBlock.CryptographicAlgorithm
	}
	if bitlen == 0 {
		bitlen = keyBlock.CryptographicLength
	}

	if alg == 0 || bitlen == 0 {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"Cryptographic Algorithm and Cryptographic Length are required",
		)
	}

	material, err := keyBlock.GetBytes()
	if err != nil {
		return nil, err
	}

	id, err := a.ImportKey(ctx, alg, bitlen, material)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.RegisterResponsePayload{
		UniqueIdentifier: id,
	}, nil
}

// handleCreateKey implements the KMIP CreateKey operation by creating a new key in transit.
func handleCreate(ctx context.Context, a Adapter, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationCreate); err != nil {
		return nil, err
	}

	alg, bitlen := AlgAndBitLenFromTemplateAttribute(req.TemplateAttribute)
	if alg == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Cryptographic algorithm is required")
	}
	if bitlen == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Cryptographic length is requiered")
	}

	name := NameFromTemplateAttribute(req.TemplateAttribute)
	id, err := a.CreateKey(ctx, name, alg, bitlen)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.CreateResponsePayload{
		ObjectType:       req.ObjectType,
		UniqueIdentifier: id,
	}, nil
}

// handleGet implements the KMIP Get for Managed Object specified by it's Unique Identifier
func handleGet(ctx context.Context, a Adapter, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationGet); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}
	obj, err := a.GetKey(ctx, uid)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.GetResponsePayload{
		ObjectType:       obj.ObjectType(),
		UniqueIdentifier: uid,
		Object:           obj,
	}, nil
}

// handleLocate - this operation requests that the server search for one or more Managed Objects,
// depending on the attributes specified in the request.
func handleLocate(ctx context.Context, a Adapter, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationLocate); err != nil {
		return nil, err
	}

	// TODO: Maximum Items, Offset Items, Storage Status Mask, and Object Group Member are skipped initially.
	ids, err := a.LocateKeys(ctx, req.Attribute)
	if err != nil {
		return nil, mapError(err)
	}
	return &payloads.LocateResponsePayload{
		UniqueIdentifier: ids,
	}, nil
}

// handleGetAttributes requests attributes associated with a ManagedObject. Object specified by it's Unique Identifier
// and the attributes by their name in the request.
func handleGetAttributes(ctx context.Context, a Adapter, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationGetAttributes); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	attrs, err := a.GetAttributes(ctx, uid, req.AttributeName)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.GetAttributesResponsePayload{
		UniqueIdentifier: uid,
		Attribute:        attrs,
	}, nil
}

// handleActivate - This operation requests the server to activate a Managed Cryptographic Object.
func handleActivate(ctx context.Context, a Adapter, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationActivate); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	if err = a.ActivateKey(ctx, uid); err != nil {
		return nil, mapError(err)
	}

	return &payloads.ActivateResponsePayload{UniqueIdentifier: uid}, nil
}

// handleRevoke - This operation requests the server to revoke a Managed Cryptographic Object or an Opaque Object.
func handleRevoke(ctx context.Context, a Adapter, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationRevoke); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// TODO: Revocation Reason, Compromise Occurrence Date are skipped intially
	if err = a.RevokeKey(ctx, uid); err != nil {
		return nil, mapError(err)
	}

	return &payloads.RevokeResponsePayload{UniqueIdentifier: uid}, nil
}

// handleDestroy - This operation is used to indicate to the server that
// the key material for the specified Managed Object SHALL be destroyed.
func handleDestroy(ctx context.Context, a Adapter, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationDestroy); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	if err = a.DestroyKey(ctx, uid); err != nil {
		return nil, mapError(err)
	}

	return &payloads.DestroyResponsePayload{UniqueIdentifier: uid}, nil
}

// === CRYPTO ADAPTER OPERATIONS === //

// handleEncrypt implement single-part only
func handleEncrypt(ctx context.Context, ca CryptoAdapter, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationEncrypt); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part Encrypt is not supported",
		)
	}

	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data (plaintext) is required")
	}
	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Encrypt")
	}
	if len(req.IVCounterNonce) > 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "IVCounterNonce is not supported")
	}
	if len(req.AuthenticatedEncryptionAdditionalData) > 0 {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"AuthenticatedEncryptionAdditionalData for Encrypt is not supported by this implementation",
		)
	}

	ct, err := ca.Encrypt(ctx, uid, req.Data)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.EncryptResponsePayload{
		UniqueIdentifier: uid,
		Data:             ct,
	}, nil
}

// handleDecrypt support only single-part Decrypt
func handleDecrypt(ctx context.Context, ca CryptoAdapter, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationDecrypt); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// Current implementation is single-part only.
	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part Decrypt is not supported",
		)
	}

	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data (ciphertext) is required")
	}

	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Decrypt")
	}
	if len(req.IVCounterNonce) > 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "IVCounterNonce is not supported")
	}
	if len(req.AuthenticatedEncryptionAdditionalData) > 0 {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"AuthenticatedEncryptionAdditionalData for Decrypt is not supported by this implementation",
		)
	}

	pt, err := ca.Decrypt(ctx, uid, req.Data)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.DecryptResponsePayload{
		UniqueIdentifier: uid,
		Data:             pt,
	}, nil
}

func handleSign(ctx context.Context, ca CryptoAdapter, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationSign); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// Current implementation is single-part only.
	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part Sign is not supported",
		)
	}

	// Current Implemetation supports only raw data input not DigestedData
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data (input to sign) is required")
	}
	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for Sign")
	}

	sig, err := ca.Sign(ctx, uid, req.Data)
	if err != nil {
		return nil, mapError(err)
	}

	return &payloads.SignResponsePayload{
		UniqueIdentifier: uid,
		SignatureData:    sig,
	}, nil
}

func handleVerify(ctx context.Context, ca CryptoAdapter, req *payloads.SignatureVerifyRequestPayload) (*payloads.SignatureVerifyResponsePayload, error) {
	if err := authOp(ctx, kmiplib.OperationSignatureVerify); err != nil {
		return nil, err
	}

	uid, err := kmipserver.GetIdOrPlaceholder(ctx, req.UniqueIdentifier)
	if err != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonInvalidField,
			"UniqueIdentifier omitted and ID Placeholder is empty",
		)
	}

	// Current implementation is single-part only.
	if len(req.CorrelationValue) > 0 || req.InitIndicator != nil || req.FinalIndicator != nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonFeatureNotSupported,
			"multi-part SignatureVerify is not supported",
		)
	}

	// Current Implemetation supports only raw data input not DigestedData
	if len(req.Data) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "Data is required")
	}
	if len(req.SignatureData) == 0 {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonInvalidField, "SignatureData is required")
	}
	if req.CryptographicParameters != nil {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonFeatureNotSupported, "CryptographicParameters is not supported for SignatureVerify")
	}

	valid, err := ca.Verify(ctx, uid, req.Data, req.SignatureData)
	if err != nil {
		return nil, mapError(err)
	}

	indicator := kmiplib.ValidityIndicatorInvalid
	if valid {
		indicator = kmiplib.ValidityIndicatorValid
	}

	return &payloads.SignatureVerifyResponsePayload{
		UniqueIdentifier:  uid,
		ValidityIndicator: indicator,
	}, nil
}
