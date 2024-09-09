// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/openbao/openbao/builtin/logical/pki/dnstest"

	"github.com/stretchr/testify/require"
)

func doACMEForDomainWithDNS(t *testing.T, dns *dnstest.TestServer, acmeClient *acme.Client, domains []string) *x509.Certificate {
	cr := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}

	return doACMEForCSRWithDNS(t, dns, acmeClient, domains, cr)
}

func doACMEForCSRWithDNS(t *testing.T, dns *dnstest.TestServer, acmeClient *acme.Client, domains []string, cr *x509.CertificateRequest) *x509.Certificate {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed to generate account key")
	acmeClient.Key = accountKey

	testCtx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelFunc()

	// Register the client.
	_, err = acmeClient.Register(testCtx, &acme.Account{Contact: []string{"mailto:ipsans@dadgarcorp.com"}}, func(tosURL string) bool { return true })
	require.NoError(t, err, "failed registering account")

	// Create the Order
	var orderIdentifiers []acme.AuthzID
	for _, domain := range domains {
		orderIdentifiers = append(orderIdentifiers, acme.AuthzID{Type: "dns", Value: domain})
	}
	order, err := acmeClient.AuthorizeOrder(testCtx, orderIdentifiers)
	require.NoError(t, err, "failed creating ACME order")

	// Fetch its authorizations.
	var auths []*acme.Authorization
	for _, authUrl := range order.AuthzURLs {
		authorization, err := acmeClient.GetAuthorization(testCtx, authUrl)
		require.NoError(t, err, "failed to lookup authorization at url: %s", authUrl)
		auths = append(auths, authorization)
	}

	// For each dns-01 challenge, place the record in the associated DNS resolver.
	var challengesToAccept []*acme.Challenge
	for _, auth := range auths {
		for _, challenge := range auth.Challenges {
			if challenge.Status != acme.StatusPending {
				t.Logf("ignoring challenge not in status pending: %v", challenge)
				continue
			}

			if challenge.Type == "dns-01" {
				challengeBody, err := acmeClient.DNS01ChallengeRecord(challenge.Token)
				require.NoError(t, err, "failed generating challenge response")

				dns.AddRecord("_acme-challenge."+auth.Identifier.Value, "TXT", challengeBody)
				defer dns.RemoveRecord("_acme-challenge."+auth.Identifier.Value, "TXT", challengeBody)

				require.NoError(t, err, "failed setting DNS record")

				challengesToAccept = append(challengesToAccept, challenge)
			}
		}
	}

	dns.PushConfig()
	require.GreaterOrEqual(t, len(challengesToAccept), 1, "Need at least one challenge, got none")

	// Tell the ACME server, that they can now validate those challenges.
	for _, challenge := range challengesToAccept {
		_, err = acmeClient.Accept(testCtx, challenge)
		require.NoError(t, err, "failed to accept challenge: %v", challenge)
	}

	// Wait for the order/challenges to be validated.
	_, err = acmeClient.WaitOrder(testCtx, order.URI)
	require.NoError(t, err, "failed waiting for order to be ready")

	// Create/sign the CSR and ask ACME server to sign it returning us the final certificate
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "failed generating P-256 certificate key")
	csr, err := x509.CreateCertificateRequest(rand.Reader, cr, csrKey)
	require.NoError(t, err, "failed generating csr")

	certs, _, err := acmeClient.CreateOrderCert(testCtx, order.FinalizeURL, csr, false)
	require.NoError(t, err, "failed to get a certificate back from ACME")

	acmeCert, err := x509.ParseCertificate(certs[0])
	require.NoError(t, err, "failed parsing acme cert bytes")

	return acmeCert
}
