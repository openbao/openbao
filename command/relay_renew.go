// Copyright (c) AppsCode Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/cli"
	remotedb "github.com/openbao/openbao/plugins/database/remote-db-plugin"
	proto "github.com/openbao/openbao/plugins/database/remote-db-plugin/proto/gen"
	"github.com/posener/complete"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RelayRenewCommand performs a one-shot renewal of the spoke's mTLS client
// cert. Uses the existing cert in -credentials-dir to authenticate to the
// hub's RenewCert RPC, then atomically replaces cert.pem and key.pem in
// place. Safe to run while `bao relay run` is up — the live gRPC connection
// keeps the old cert until it reconnects, at which point the renewed cert is
// used.
type RelayRenewCommand struct {
	*BaseCommand

	flagServer         string
	flagServerName     string
	flagCredentialsDir string
	flagTTL            time.Duration
}

var (
	_ cli.Command             = (*RelayRenewCommand)(nil)
	_ cli.CommandAutocomplete = (*RelayRenewCommand)(nil)
)

func (c *RelayRenewCommand) Synopsis() string {
	return "Renew the spoke's mTLS client cert via the existing cert"
}

func (c *RelayRenewCommand) Help() string {
	return strings.TrimSpace(`
Usage: bao relay renew [options]

  Renews the spoke's mTLS client cert without a fresh bootstrap token. The
  existing cert in -credentials-dir authenticates the call; the hub signs
  the new CSR via the spoke-CA.

  The renewed cert is written atomically over cert.pem and key.pem. ca.pem
  is left untouched.

  Pair with cron, systemd timers, or just let 'bao relay run' renew
  automatically (see its -renew-* flags).

` + c.Flags().Help())
}

func (c *RelayRenewCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetNone)
	f := set.NewFlagSet("Command Options")

	f.StringVar(&StringVar{
		Name:    "server",
		Target:  &c.flagServer,
		Default: "localhost:50053",
		Usage:   "Hub gRPC address (host:port).",
	})
	f.StringVar(&StringVar{
		Name:    "credentials-dir",
		Target:  &c.flagCredentialsDir,
		Default: "/etc/openbao-spoke",
		Usage:   "Directory containing cert.pem, key.pem, ca.pem.",
	})
	f.StringVar(&StringVar{
		Name:    "server-name",
		Target:  &c.flagServerName,
		Default: "",
		Usage:   "Override SNI / expected hub CN (defaults to the host part of -server).",
	})
	f.DurationVar(&DurationVar{
		Name:    "ttl",
		Target:  &c.flagTTL,
		Default: 0,
		Usage:   "Requested cert validity. 0 = hub default (~30d).",
	})
	return set
}

func (c *RelayRenewCommand) AutocompleteArgs() complete.Predictor { return nil }
func (c *RelayRenewCommand) AutocompleteFlags() complete.Flags    { return c.Flags().Completions() }

func (c *RelayRenewCommand) Run(args []string) int {
	if err := c.Flags().Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}
	res, err := RenewSpokeCert(context.Background(), RenewSpokeCertInput{
		Server:         c.flagServer,
		ServerName:     c.flagServerName,
		CredentialsDir: c.flagCredentialsDir,
		TTL:            c.flagTTL,
	})
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}
	c.UI.Output(fmt.Sprintf("Renewed cert for %q.", res.CommonName))
	c.UI.Output(fmt.Sprintf("New expiry: %s (in %s)",
		res.NotAfter.UTC().Format(time.RFC3339),
		shortDuration(time.Until(res.NotAfter))))
	return 0
}

// --- Shared helper (also used by `bao relay run`'s auto-renew goroutine) ----

// RenewSpokeCertInput configures one renewal call.
type RenewSpokeCertInput struct {
	Server         string
	ServerName     string
	CredentialsDir string
	TTL            time.Duration
}

// RenewSpokeCertResult reports the metadata of the new cert.
type RenewSpokeCertResult struct {
	CommonName string
	NotAfter   time.Time
}

// RenewSpokeCert loads the existing credentials, builds a fresh CSR for the
// same CN, calls the hub's RenewCert RPC over mTLS, and writes the new cert +
// key into the credentials directory atomically.
//
// The hub is not strictly required for verifying the swap — the function
// only mutates disk on success. ca.pem is left in place: the spoke-CA does
// not change on renewal, only the leaf cert.
func RenewSpokeCert(ctx context.Context, in RenewSpokeCertInput) (*RenewSpokeCertResult, error) {
	tlsCfg, err := loadSpokeTLS(in.CredentialsDir, in.ServerName, in.Server)
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}
	cn := tlsCfg.Certificates[0].Leaf.Subject.CommonName

	key, csrPEM, err := generateRenewalCSR(cn)
	if err != nil {
		return nil, fmt.Errorf("generate CSR: %w", err)
	}

	conn, err := grpc.NewClient(
		in.Server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(remotedb.MaxMessageBytes),
			grpc.MaxCallSendMsgSize(remotedb.MaxMessageBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial hub: %w", err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := proto.NewAgentServiceClient(conn).RenewCert(ctx, &proto.RenewCertRequest{
		CsrPem:     csrPEM,
		TtlSeconds: int64(in.TTL / time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("renew: %w", err)
	}
	if len(resp.CertPem) == 0 {
		return nil, fmt.Errorf("hub returned an empty cert")
	}

	// Sanity-check the cert we got back before touching disk.
	newCert, err := parseFirstCert(resp.CertPem)
	if err != nil {
		return nil, fmt.Errorf("parse returned cert: %w", err)
	}
	if newCert.Subject.CommonName != cn {
		return nil, fmt.Errorf("renewed cert CN %q does not match %q",
			newCert.Subject.CommonName, cn)
	}

	keyPEM, err := marshalECKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeRenewedCreds(in.CredentialsDir, resp.CertPem, keyPEM); err != nil {
		return nil, fmt.Errorf("persist credentials: %w", err)
	}
	return &RenewSpokeCertResult{
		CommonName: cn,
		NotAfter:   newCert.NotAfter,
	}, nil
}

// generateRenewalCSR creates a fresh keypair + CSR with the same CN as the
// caller's current cert. A fresh key on every renewal keeps the long-term
// secret moving, even if the cert itself just rotates.
func generateRenewalCSR(cn string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func marshalECKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseFirstCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}
	return x509.ParseCertificate(block.Bytes)
}

// writeRenewedCreds writes cert and key to .new files, fsyncs each, renames
// them into place, then fsyncs the directory so the rename is durable.
//
// Without the directory sync, a clean reboot between the cert rename and the
// key rename leaves the disk with (new cert, old key); tls.LoadX509KeyPair
// at next start would fail until the operator re-ran relay renew. With the
// sync, the worst-case observable state on recovery is (new cert, old key)
// — which fails the LoadX509KeyPair signature check loudly so the caller
// retries — or the fully-committed (new cert, new key).
//
// Order matters. tls.LoadX509KeyPair reads cert.pem first and then key.pem;
// a concurrent reader sandwiched between the two renames sees whichever pair
// we leave it. We rename the cert FIRST so the brief observable state is
// (new cert, old key) — which fails the LoadX509KeyPair signature check
// loudly, the caller retries, and the next attempt sees (new cert, new key).
// Doing it the other way around — key first, then cert — leaves (old cert,
// new key) visible, which silently mismatches at handshake time and is much
// harder to recover from in the renewal goroutine that just successfully
// renewed.
func writeRenewedCreds(dir string, certPEM, keyPEM []byte) error {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	tmpCert := certPath + ".new"
	tmpKey := keyPath + ".new"

	if err := writeFileSync(tmpCert, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileSync(tmpKey, keyPEM, 0o600); err != nil {
		_ = os.Remove(tmpCert)
		return err
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		_ = os.Remove(tmpKey)
		return err
	}
	// Sync the directory so the cert rename is durable before we attempt
	// the key rename. Without this a power cut between the two renames can
	// leave the directory entry pointing at the old cert despite the kernel
	// having already returned success from Rename(tmpCert, certPath).
	if err := syncDir(dir); err != nil {
		return err
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		return err
	}
	return syncDir(dir)
}

// CurrentSpokeCertExpiry reads cert.pem from credsDir and returns its
// NotAfter, used by the daemon's auto-renewal scheduler.
func CurrentSpokeCertExpiry(credsDir string) (time.Time, error) {
	pemBytes, err := os.ReadFile(filepath.Join(credsDir, "cert.pem"))
	if err != nil {
		return time.Time{}, err
	}
	cert, err := parseFirstCert(pemBytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// CurrentSpokeCertWindow returns NotBefore and NotAfter of cert.pem, used to
// decide whether the cert is past its renewal threshold (e.g. half-life).
func CurrentSpokeCertWindow(credsDir string) (time.Time, time.Time, error) {
	pemBytes, err := os.ReadFile(filepath.Join(credsDir, "cert.pem"))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	cert, err := parseFirstCert(pemBytes)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return cert.NotBefore, cert.NotAfter, nil
}

// PastRenewalThreshold returns true when now is past the renewal threshold,
// computed as NotBefore + threshold*(NotAfter - NotBefore). threshold of 0.5
// means "renew at half-life".
func PastRenewalThreshold(notBefore, notAfter time.Time, threshold float64, now time.Time) bool {
	lifetime := notAfter.Sub(notBefore)
	cutoff := notBefore.Add(time.Duration(float64(lifetime) * threshold))
	return !now.Before(cutoff)
}

// loadSpokeTLS is reused from relay_run.go. Marker comment so the file is
// self-contained when read in isolation.
var _ = tls.LoadX509KeyPair
