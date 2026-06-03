package transit

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/openbao/openbao/builtin/logical/transit/kmip"
	"github.com/openbao/openbao/helper/testhelpers/certhelpers"
	"github.com/openbao/openbao/sdk/v2/logical"
	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/stretchr/testify/require"
)

func testKmip(t *testing.T, closure func(c *kmipclient.Client)) {
	t.Helper()
	t.Parallel()

	c, _, _ := startKmip(t)
	seedKmipFixtures(t, c)
	closure(c)
}

func startKmip(t *testing.T) (*kmipclient.Client, string, certhelpers.Certificate) {
	t.Helper()

	b, storage := createBackendWithStorage(t)
	ctx := t.Context()

	ca := certhelpers.NewCert(
		t,
		certhelpers.CommonName("test-kmip-ca"),
		certhelpers.IsCA(true),
		certhelpers.SelfSign(),
	)
	serverCert := certhelpers.NewCert(
		t,
		certhelpers.CommonName("localhost"),
		certhelpers.Parent(ca),
		certhelpers.IP("127.0.0.1"),
		certhelpers.DNS("localhost"),
	)
	clientCert := certhelpers.NewCert(
		t,
		certhelpers.CommonName("test-kmip-client"),
		certhelpers.Parent(ca),
	)

	// Enable the server. No KMIP op exists for this, so it goes through the backend.
	// listen_addr :0 => OS-assigned port.
	// restartKmipServer binds the listener synchronously before returning, so Addr() is valid immediately.
	cfgResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/kmip",
		Storage:   storage,
		Data: map[string]interface{}{
			"enabled":             true,
			"listen_addr":         "127.0.0.1:0",
			"server_cert_pem":     string(serverCert.Pem),
			"server_key_pem":      string(serverCert.PrivKey.Pem),
			"tls_ca_cert_pem":     string(ca.Pem),
			"require_client_cert": true,
		},
	})
	require.NoError(t, err)
	require.Falsef(t, cfgResp != nil && cfgResp.IsError(), "enable kmip: %#v", cfgResp)

	// Role bound to the client cert's exact Subject DN, granting every op.
	roleResp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "kmip/roles/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"cert_subject_dn":    clientCert.Template.Subject.String(),
			"allowed_operations": kmip.ValidOperations(),
		},
	})
	require.NoError(t, err)
	require.Falsef(t, roleResp != nil && roleResp.IsError(), "create role: %#v", roleResp)

	t.Cleanup(func() { b.stopKmipServer() })

	require.NotNil(t, b.kmipServer, "KMIP server should be running after config write")
	addr := b.kmipServer.Addr()
	client := dialKmipClient(t, addr, ca.Pem, clientCert.Pem, clientCert.PrivKey.Pem)
	return client, addr, ca
}

func dialKmipClient(t *testing.T, addr string, caCertPEM, clientCertPEM, clientKeyPEM []byte) *kmipclient.Client {
	t.Helper()

	opts := []kmipclient.Option{
		kmipclient.WithRootCAPem(caCertPEM),
		kmipclient.WithServerName("localhost"),
	}
	if len(clientCertPEM) > 0 {
		opts = append(opts, kmipclient.WithClientCertPEM(clientCertPEM, clientKeyPEM))
	}

	c, err := kmipclient.Dial(addr, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	return c
}

// Fixture keys seeded before every testKmip closure runs. UniqueIdentifier == name.
const (
	fixtureAESKey = "kmip-aes" // aes256-gcm96, created via KMIP Create
	fixtureRSAKey = "kmip-rsa" // rsa-2048, imported via KMIP Register
)

// seedKmipFixtures creates the fixture keys using the connected KMIP client.
func seedKmipFixtures(t *testing.T, c *kmipclient.Client) {
	t.Helper()

	// Symmetric key for Get / Locate / Encrypt / Decrypt.
	_, err := c.Create().
		AES(256, kmiplib.CryptographicUsageEncrypt|kmiplib.CryptographicUsageDecrypt).
		WithName(fixtureAESKey).
		Exec()
	require.NoError(t, err)

	// Asymmetric key for Sign / Verify. The server supports symmetric Create only,
	// so RSA is imported via Register. NOTE: WithKeyFormat(PKCS8) is REQUIRED — the
	// client defaults RSA private keys to PKCS#1, which handleRegister rejects
	// (kmip/handlers.go:129 wants KeyFormatTypePKCS_8).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = c.Register().
		WithKeyFormat(kmipclient.PKCS8).
		RsaPrivateKey(priv, kmiplib.CryptographicUsageSign|kmiplib.CryptographicUsageVerify).
		WithName(fixtureRSAKey).
		Exec()
	require.NoError(t, err)
}
