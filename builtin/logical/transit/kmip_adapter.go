// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/builtin/logical/transit/kmip"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

type transitAdapter struct {
	b *backend
	s logical.Storage
}

var (
	_ kmip.Adapter       = (*transitAdapter)(nil)
	_ kmip.CryptoAdapter = (*transitAdapter)(nil)
)

// AuthenticateCert returns allowed operations by subject DN.
func (a *transitAdapter) AuthenticateCert(ctx context.Context, subjectDN string) (allowedOps []string, err error) {
	role, err := a.b.findKmipRoleByDN(ctx, a.s, subjectDN)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, kmip.ErrNoRole
	}

	return role.AllowedOps, nil
}

// CreateKey creates a new key. KMIP algorithm and bit length come directly from the request, adapter converts to specific type.
// If name is empty (client did not supply a Name attribute), a UUID is generated and used as the UniqueIdentifier.
func (a *transitAdapter) CreateKey(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32) (string, error) {
	kt, _, err := keyTypeFor(alg, bitlen)
	if err != nil {
		return "", err
	}
	if name == "" {
		name, err = uuid.GenerateUUID()
		if err != nil {
			return "", err
		}
	}
	p, upserted, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    name,
			KeyType: kt,
			Upsert:  true,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return "", err
	}
	if p == nil {
		return "", fmt.Errorf("create %q: nil policy", name)
	}

	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	if !upserted {
		return "", fmt.Errorf("key %q already exists", name)
	}
	return name, nil
}

// ImportKey imports raw key material:
//   - symmetric: raw bytes
//   - asymmetric: PKCS8 DER
//
// If name is empty (client did not supply a Name attribute), a UUID is generated and used as the UniqueIdentifier.
// If name is supplied and a policy with that name already exists, the import is rejected — KMIP Register creates
// a new managed object, whereas transit's ImportPolicy would otherwise add a new key version to the existing policy.
func (a *transitAdapter) ImportKey(ctx context.Context, name string, alg kmiplib.CryptographicAlgorithm, bitlen int32, keyMaterial []byte) (string, error) {
	kt, isPriv, err := keyTypeFor(alg, bitlen)
	if err != nil {
		return "", err
	}
	if name == "" {
		name, err = uuid.GenerateUUID()
		if err != nil {
			return "", err
		}
	} else {
		existing, _, err := a.b.GetPolicy(ctx, keysutil.PolicyRequest{
			Storage: a.s,
			Name:    name,
		}, a.b.GetRandomReader())
		if err != nil {
			return "", err
		}
		if existing != nil {
			if a.b.System().CachingDisabled() {
				existing.Unlock()
			}
			return "", fmt.Errorf("key %q already exists", name)
		}
	}
	err = a.b.lm.ImportPolicy(ctx, keysutil.PolicyRequest{
		Storage:                  a.s,
		Name:                     name,
		KeyType:                  kt,
		AllowImportedKeyRotation: true,
		IsPrivateKey:             isPriv,
	}, keyMaterial, a.b.GetRandomReader())
	if err != nil {
		return "", fmt.Errorf("import %q: %w", name, err)
	}
	return name, nil
}

// GetKey retrieves key material for a given unique id.
func (a *transitAdapter) GetKey(ctx context.Context, id string) (kmiplib.Object, error) {
	p, _, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    id,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	// ToDo: Check if we need implement same logic as in pathPolicyExportRead if p.Exportable or not

	versionStr := strconv.Itoa(p.LatestVersion)
	keyEntry, ok := p.Keys[versionStr]
	if !ok {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "key version %s not found", versionStr)
	}

	return keyEntryToKmipObject(keyEntry, p.Type)
}

// GetAttributes returns KMIP attributes for a key. Returns all attributes if names is empty.
func (a *transitAdapter) GetAttributes(ctx context.Context, id string, names []kmiplib.AttributeName) ([]kmiplib.Attribute, error) {
	p, _, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    id,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	versionStr := strconv.Itoa(p.LatestVersion)
	keyEntry, ok := p.Keys[versionStr]
	if !ok {
		return nil, kmipserver.Errorf(kmiplib.ResultReasonGeneralFailure, "key version %s not found", versionStr)
	}

	alg, bitlen, objType, err := kmipAttrsForPolicy(keyEntry, p.Type)
	if err != nil {
		return nil, err
	}

	attrs := []kmiplib.Attribute{
		{AttributeName: kmiplib.AttributeNameName, AttributeValue: kmiplib.Name{NameValue: p.Name, NameType: kmiplib.NameTypeUninterpretedTextString}},
		{AttributeName: kmiplib.AttributeNameObjectType, AttributeValue: objType},
		{AttributeName: kmiplib.AttributeNameCryptographicAlgorithm, AttributeValue: alg},
		{AttributeName: kmiplib.AttributeNameCryptographicLength, AttributeValue: int32(bitlen)},
		{AttributeName: kmiplib.AttributeNameState, AttributeValue: kmiplib.StateActive},
	}
	if len(names) == 0 {
		return attrs, nil
	}

	filtered := make([]kmiplib.Attribute, 0, len(names))
	for _, want := range names {
		for _, attr := range attrs {
			if attr.AttributeName == want {
				filtered = append(filtered, attr)
			}
		}
	}

	return filtered, nil
}

// LocateKeys returns a []IDs of keys matching attrs.
// Returns only non-revoked keys, empty []attr means return all active keys.
//
// TODO: support additional Locate filters (still AND across all):
//   - State?
//   - CryptographicAlgorithm
//   - CryptographicLength
//   - CryptographicUsageMask
//   - UniqueIdentifier
//
// TODO: MaximumItems / OffsetItems ?
func (a *transitAdapter) LocateKeys(ctx context.Context, attrs []kmiplib.Attribute) ([]string, error) {
	var (
		wantName       string
		wantObjectType kmiplib.ObjectType
	)
	for _, attr := range attrs {
		switch attr.AttributeName {
		case kmiplib.AttributeNameName:
			n, ok := attr.AttributeValue.(kmiplib.Name)
			if !ok || n.NameValue == "" {
				return nil, kmipserver.Errorf(
					kmiplib.ResultReasonInvalidField,
					"Name attribute is empty or invalid",
				)
			}
			if wantName != "" && wantName != n.NameValue {
				return nil, nil
			}
			wantName = n.NameValue
		case kmiplib.AttributeNameObjectType:
			ot, ok := attr.AttributeValue.(kmiplib.ObjectType)
			if !ok {
				return nil, kmipserver.Errorf(
					kmiplib.ResultReasonInvalidField,
					"ObjectType attribute has invalid value",
				)
			}
			if wantObjectType != 0 && wantObjectType != ot {
				return nil, nil
			}
			wantObjectType = ot
		default:
			return nil, kmipserver.Errorf(
				kmiplib.ResultReasonOperationNotSupported,
				"Locate filter %s is not supported", attr.AttributeName,
			)
		}
	}

	// no Name and no ObjectType → just list.
	if wantName == "" && wantObjectType == 0 {
		return a.s.List(ctx, "policy/")
	}

	candidates := []string{wantName}
	if wantName == "" {
		keys, err := a.s.List(ctx, "policy/")
		if err != nil {
			return nil, err
		}
		candidates = keys
	}

	// Closure so defer p.Unlock() is scoped per candidate.
	matches := func(name string) (bool, error) {
		p, _, err := a.b.GetPolicy(
			ctx,
			keysutil.PolicyRequest{Storage: a.s, Name: name},
			a.b.GetRandomReader(),
		)
		if err != nil {
			return false, err
		}
		if p == nil {
			return false, nil
		}
		if !a.b.System().CachingDisabled() {
			p.Lock(false)
		}
		defer p.Unlock()

		if wantObjectType == 0 {
			return true, nil
		}
		versionStr := strconv.Itoa(p.LatestVersion)
		keyEntry, ok := p.Keys[versionStr]
		if !ok {
			return false, nil
		}
		_, _, objType, err := kmipAttrsForPolicy(keyEntry, p.Type)
		if err != nil {
			return false, err
		}
		return objType == wantObjectType, nil
	}

	out := make([]string, 0, len(candidates))
	for _, name := range candidates {
		ok, err := matches(name)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, name)
		}
	}
	return out, nil
}

// ActivateKey activates a key.
func (a *transitAdapter) ActivateKey(ctx context.Context, id string) error { return nil }

// RevokeKey marks a key as revoked.
func (a *transitAdapter) RevokeKey(ctx context.Context, id string) error { return nil }

// DestroyKey destroys a key permanently.
func (a *transitAdapter) DestroyKey(ctx context.Context, id string) error {
	return a.b.lm.DeletePolicy(ctx, a.s, id)
}

// Logger returns the logger for the backend.
func (a *transitAdapter) Logger() hclog.Logger { return a.b.Logger() }

func (a *transitAdapter) Encrypt(ctx context.Context, id string, plaintext []byte) ([]byte, error) {
	p, _, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    id,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	pt, err := p.EncryptWithFactory(p.LatestVersion, nil, nil, string(plaintext), nil)
	if err != nil {
		return nil, err
	}

	return []byte(pt), nil
}

func (a *transitAdapter) Decrypt(ctx context.Context, id string, ciphertext []byte) ([]byte, error) {
	p, _, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    id,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	pt, err := p.DecryptWithFactory(nil, nil, string(ciphertext), nil)
	if err != nil {
		return nil, err
	}

	return []byte(pt), nil
}

func (a *transitAdapter) Sign(ctx context.Context, id string, data []byte) ([]byte, error) {
	p, _, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    id,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	res, err := p.Sign(p.LatestVersion, nil, data, keysutil.HashTypeSHA2256, "", keysutil.MarshalingTypeASN1)
	if err != nil {
		return nil, err
	}
	return []byte(res.Signature), nil
}

func (a *transitAdapter) Verify(ctx context.Context, id string, data, signature []byte) (bool, error) {
	p, _, err := a.b.GetPolicy(
		ctx,
		keysutil.PolicyRequest{
			Storage: a.s,
			Name:    id,
		},
		a.b.GetRandomReader(),
	)
	if err != nil {
		return false, err
	}
	if p == nil {
		return false, nil
	}
	if !a.b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	return p.VerifySignature(nil, data, keysutil.HashTypeSHA2256, "", keysutil.MarshalingTypeASN1, string(signature))
}
