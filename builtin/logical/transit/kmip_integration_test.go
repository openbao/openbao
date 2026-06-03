// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"testing"

	"github.com/openbao/openbao/helper/testhelpers/certhelpers"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/stretchr/testify/require"
)

func TestKmip_Query(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		resp, err := c.Query().Operations().Objects().ServerInformation().Exec()
		require.NoError(t, err)
		require.Contains(t, resp.Operations, kmiplib.OperationCreate)
		require.Contains(t, resp.Operations, kmiplib.OperationEncrypt)
		require.Contains(t, resp.ObjectType, kmiplib.ObjectTypeSymmetricKey)
		require.Equal(t, "OpenBao Transit KMIP", resp.VendorIdentification)
	})
}

func TestKmip_CreateAndGet(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		create, err := c.Create().
			AES(256, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt).
			WithName("created-aes").
			Exec()
		require.NoError(t, err)
		require.Equal(t, "created-aes", create.UniqueIdentifier) // UID == transit policy name

		get, err := c.Get(create.UniqueIdentifier).Exec()
		require.NoError(t, err)
		require.Equal(t, kmiplib.ObjectTypeSymmetricKey, get.ObjectType)
		require.Equal(t, create.UniqueIdentifier, get.UniqueIdentifier)
		require.NotNil(t, get.Object)
	})
}

func TestKmip_Locate(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		// by name → exactly the fixture key
		byName, err := c.Locate().WithName(fixtureAESKey).Exec()
		require.NoError(t, err)
		require.Equal(t, []string{fixtureAESKey}, byName.UniqueIdentifier)

		// by object type → fixture key present
		all, err := c.Locate().WithObjectType(kmiplib.ObjectTypeSymmetricKey).Exec()
		require.NoError(t, err)
		require.Contains(t, all.UniqueIdentifier, fixtureAESKey)
	})
}

// TODO: Pagination should be fixed, right now happens in handler, which is wrong.
func TestKmip_LocatePagination(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		// seed a few more keys so pagination is observable
		for _, n := range []string{"page-a", "page-b", "page-c"} {
			_, err := c.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName(n).Exec()
			require.NoError(t, err)
		}

		first, err := c.Locate().WithMaxItems(2).Exec()
		require.NoError(t, err)
		require.Len(t, first.UniqueIdentifier, 2)
		require.NotNil(t, first.LocatedItems)
		require.GreaterOrEqual(t, *first.LocatedItems, int32(2))

		next, err := c.Locate().WithOffset(2).WithMaxItems(2).Exec()
		require.NoError(t, err)
		require.NotEmpty(t, next.UniqueIdentifier)
		require.NotEqual(t, first.UniqueIdentifier, next.UniqueIdentifier)
	})
}

func TestKmip_GetAttributes(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		resp, err := c.GetAttributes(fixtureAESKey).
			WithAttributes(
				kmiplib.AttributeNameCryptographicAlgorithm,
				kmiplib.AttributeNameCryptographicLength,
				kmiplib.AttributeNameObjectType,
				kmiplib.AttributeNameState,
			).
			Exec()
		require.NoError(t, err)

		got := map[kmiplib.AttributeName]any{}
		for _, a := range resp.Attribute {
			got[a.AttributeName] = a.AttributeValue
		}
		require.Equal(t, kmiplib.CryptographicAlgorithmAES, got[kmiplib.AttributeNameCryptographicAlgorithm])
		require.Equal(t, int32(256), got[kmiplib.AttributeNameCryptographicLength])
		require.Equal(t, kmiplib.ObjectTypeSymmetricKey, got[kmiplib.AttributeNameObjectType])
		require.Equal(t, kmiplib.StateActive, got[kmiplib.AttributeNameState])
	})
}

func TestKmip_EncryptDecrypt(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		plaintext := []byte("super-secret-payload")

		enc, err := c.Encrypt(fixtureAESKey).Data(plaintext).Exec()
		require.NoError(t, err)
		require.NotEmpty(t, enc.Data) // transit ciphertext bytes (vault:v1:...)

		dec, err := c.Decrypt(fixtureAESKey).Data(enc.Data).Exec()
		require.NoError(t, err)
		require.Equal(t, plaintext, dec.Data)
	})
}

func TestKmip_SignVerify(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		data := []byte("data-to-sign")

		sign, err := c.Sign(fixtureRSAKey).Data(data).Exec()
		require.NoError(t, err)
		require.NotEmpty(t, sign.SignatureData)

		verify, err := c.SignatureVerify(fixtureRSAKey).Data(data).Signature(sign.SignatureData).Exec()
		require.NoError(t, err)
		require.Equal(t, kmiplib.ValidityIndicatorValid, verify.ValidityIndicator)
	})
}

func TestKmip_RegisterImport(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		raw := make([]byte, 32) // 256-bit AES material
		for i := range raw {
			raw[i] = byte(i)
		}

		reg, err := c.Register().
			SymmetricKey(kmiplib.CryptographicAlgorithmAES,
				kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt, raw).
			WithName("imported-aes").
			Exec()
		require.NoError(t, err)
		require.Equal(t, "imported-aes", reg.UniqueIdentifier)

		// imported key is usable
		enc, err := c.Encrypt(reg.UniqueIdentifier).Data([]byte("x")).Exec()
		require.NoError(t, err)
		require.NotEmpty(t, enc.Data)
	})
}

func TestKmip_Destroy(t *testing.T) {
	testKmip(t, func(c *kmipclient.Client) {
		create, err := c.Create().AES(256, kmiplib.CryptographicUsageEncrypt).WithName("to-destroy").Exec()
		require.NoError(t, err)

		_, err = c.Destroy(create.UniqueIdentifier).Exec()
		require.NoError(t, err)

		_, err = c.Get(create.UniqueIdentifier).Exec() // gone
		require.Error(t, err)
	})
}

func TestKmip_AuthDenied(t *testing.T) {
	t.Parallel()
	_, addr, ca := startKmip(t) // server up; ignore the authorized client

	// Signed by the same CA → TLS handshake succeeds, but "CN=intruder" maps to no role.
	// The server denies the very first operation — Dial itself fails.
	intruderCert := certhelpers.NewCert(
		t,
		certhelpers.CommonName("intruder"),
		certhelpers.Parent(ca),
	)
	_, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem(ca.Pem),
		kmipclient.WithServerName("localhost"),
		kmipclient.WithClientCertPEM(intruderCert.Pem, intruderCert.PrivKey.Pem),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "no matching role")
}
