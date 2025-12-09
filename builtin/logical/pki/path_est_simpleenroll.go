// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// pathEstSimpleEnroll wires the authenticated EST /simpleenroll endpoint.
func pathEstSimpleEnroll(b *backend) []*framework.Path {
	return buildEstFrameworkPaths(b, patternEstSimpleEnroll, "/simpleenroll")
}

func patternEstSimpleEnroll(b *backend, pattern string) *framework.Path {
	fields := map[string]*framework.FieldSchema{}

	if strings.Contains(pattern, "roles/") {
		fields["role"] = &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "The desired role to use for EST operations",
			Required:    true,
		}
	}

	if strings.Contains(pattern, ".well-known/est/") && strings.Count(pattern, "/") > 2 {
		fields["label"] = &framework.FieldSchema{
			Type:        framework.TypeString,
			Description: "The EST label for routing to specific configuration",
			Required:    true,
		}
	}

	return &framework.Path{
		Pattern: pattern,
		Fields:  fields,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "est-simple-enroll",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathEstSimpleEnrollWrite,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    "EST simpleenroll endpoint - enrolls a new certificate",
		HelpDescription: "This endpoint accepts a PKCS#10 CSR in PKCS#7 format (base64 encoded) and returns a signed certificate per RFC 7030.",
	}
}

func (b *backend) pathEstSimpleEnrollWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleEstSimpleEnroll(ctx, req, data, estSimpleEnrollOptions{})
}

// handleEstSimpleEnroll contains the shared CSR parsing and signing flow used by both EST endpoints.
func (b *backend) handleEstSimpleEnroll(ctx context.Context, req *logical.Request, data *framework.FieldData, opts estSimpleEnrollOptions) (*logical.Response, error) {
	config, err := b.requireEstAuthentication(ctx, req, data)
	if err != nil {
		return estUnauthorizedResponse(err.Error()), nil
	}

	var clientCert *x509.Certificate
	if opts.requireTLSClientCert || opts.enforceCSRMatchesTLSCertIdentity {
		clientCert, err = extractTLSClientCertificate(req)
		if err != nil {
			return estUnauthorizedResponse(err.Error()), nil
		}
	}

	pathPolicy, err := resolveEstPathPolicy(config, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	bodyData, err := readEstCSRPayload(req)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	csr, err := extractCSRFromPKCS7EST(bodyData)
	if err != nil {
		return logical.ErrorResponse("failed to parse CSR: %v", err), logical.ErrInvalidRequest
	}

	if err := csr.CheckSignature(); err != nil {
		return logical.ErrorResponse("invalid CSR signature: %v", err), logical.ErrInvalidRequest
	}

	if opts.enforceCSRMatchesTLSCertIdentity {
		if err := ensureCSRMatchesClientCertificateIdentity(csr, clientCert); err != nil {
			return logical.ErrorResponse("csr does not match authenticated certificate: %v", err), logical.ErrInvalidRequest
		}
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	signData := buildEstSignFieldData(string(csrPEM))
	signResp, err := b.signEstCertificate(ctx, req, signData, pathPolicy)
	if err != nil {
		return nil, err
	}
	if signResp == nil || signResp.Data == nil {
		return logical.ErrorResponse("failed to sign certificate"), nil
	}

	certPEM, ok := signResp.Data["certificate"].(string)
	if !ok {
		return logical.ErrorResponse("no certificate in signing response"), nil
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return logical.ErrorResponse("failed to decode certificate PEM"), nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return logical.ErrorResponse("failed to parse certificate: %v", err), nil
	}

	pkcs7Cert, err := createPKCS7CertsOnly([]*x509.Certificate{cert})
	if err != nil {
		return nil, fmt.Errorf("error creating PKCS#7 certificate: %w", err)
	}

	base64Cert := base64.StdEncoding.EncodeToString(pkcs7Cert)

	return &logical.Response{
		Data: map[string]interface{}{
			"http_status_code":               200,
			"http_content_type":              estPKCS7ContentType,
			"http_content_transfer_encoding": "base64",
			"http_raw_body":                  []byte(base64Cert),
		},
	}, nil
}

func resolveEstPathPolicy(config *estConfigEntry, data *framework.FieldData) (string, error) {
	pathPolicy := ""

	label, labelOk := data.GetOk("label")
	if labelOk && label.(string) != "" {
		labelName := label.(string)
		if labelPolicy, exists := config.LabelToPathPolicy[labelName]; exists {
			pathPolicy = labelPolicy
		} else {
			return "", fmt.Errorf("EST label not found: %s", labelName)
		}
	} else {
		roleName, roleOk := data.GetOk("role")
		if roleOk && roleName.(string) != "" {
			pathPolicy = "role:" + roleName.(string)
		} else {
			pathPolicy = config.DefaultPathPolicy
		}
	}

	if pathPolicy == "" {
		return "", fmt.Errorf("no path policy configured for this EST endpoint")
	}

	return pathPolicy, nil
}

func readEstCSRPayload(req *logical.Request) ([]byte, error) {
	if req.HTTPRequest == nil || req.HTTPRequest.Body == nil {
		return nil, fmt.Errorf("no CSR data provided in request body")
	}

	bodyData, err := io.ReadAll(io.LimitReader(req.HTTPRequest.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	defer func() {
		if cerr := req.HTTPRequest.Body.Close(); cerr != nil {
			fmt.Println("failed to close request body: %v", cerr)
		}
	}()

	if len(bodyData) == 0 {
		return nil, fmt.Errorf("empty request body")
	}

	if req.HTTPRequest.Header.Get("Content-Transfer-Encoding") == "base64" {
		decodedData, err := base64.StdEncoding.DecodeString(string(bodyData))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 CSR: %v", err)
		}
		bodyData = decodedData
	}

	return bodyData, nil
}

func buildEstSignFieldData(csr string) *framework.FieldData {
	schema := addNonCACommonFields(map[string]*framework.FieldSchema{})
	schema["csr"] = &framework.FieldSchema{Type: framework.TypeString, Description: "PEM-format CSR to be signed"}

	return &framework.FieldData{
		Raw: map[string]interface{}{
			"csr":        csr,
			"format":     "pem",
			"issuer_ref": defaultRef,
		},
		Schema: schema,
	}
}

func (b *backend) signEstCertificate(ctx context.Context, req *logical.Request, signData *framework.FieldData, pathPolicy string) (*logical.Response, error) {
	if pathPolicy == "sign-verbatim" {
		role := buildSignVerbatimRoleWithNoData(nil)
		return b.pathIssueSignCert(ctx, req, signData, role, true, true)
	}

	if len(pathPolicy) > 5 && strings.HasPrefix(pathPolicy, "role:") {
		roleName := pathPolicy[5:]
		role, err := b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, fmt.Errorf("failed to load role %s: %w", roleName, err)
		}
		if role == nil {
			return logical.ErrorResponse("role not found: %s", roleName), logical.ErrInvalidRequest
		}
		return b.pathIssueSignCert(ctx, req, signData, role, true, false)
	}

	return logical.ErrorResponse("invalid path policy: %s", pathPolicy), logical.ErrInvalidRequest
}

type estSimpleEnrollOptions struct {
	requireTLSClientCert             bool
	enforceCSRMatchesTLSCertIdentity bool
}

func estUnauthorizedResponse(reason string) *logical.Response {
	message := "Unauthorized"
	if reason != "" {
		message += ": " + reason
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"http_status_code":                401,
			"http_content_type":               "text/plain",
			"http_raw_body":                   []byte(message),
			logical.HTTPWWWAuthenticateHeader: consts.ESTWWWAuthenticateHeaderValue,
		},
	}
}

func extractTLSClientCertificate(req *logical.Request) (*x509.Certificate, error) {
	if req.HTTPRequest == nil || req.HTTPRequest.TLS == nil {
		return nil, fmt.Errorf("TLS client authentication required for EST simplereenroll")
	}

	if len(req.HTTPRequest.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("client certificate missing in TLS handshake")
	}

	return req.HTTPRequest.TLS.PeerCertificates[0], nil
}

func ensureCSRMatchesClientCertificateIdentity(csr *x509.CertificateRequest, cert *x509.Certificate) error {
	if csr == nil || cert == nil {
		return fmt.Errorf("missing CSR or authenticated certificate")
	}

	if !bytes.Equal(cert.RawSubject, csr.RawSubject) {
		return fmt.Errorf("subject mismatch")
	}

	if !compareStringSets(csr.DNSNames, cert.DNSNames) {
		return fmt.Errorf("DNS names differ")
	}

	if !compareStringSets(csr.EmailAddresses, cert.EmailAddresses) {
		return fmt.Errorf("email addresses differ")
	}

	if !compareIPSets(csr.IPAddresses, cert.IPAddresses) {
		return fmt.Errorf("IP Subject Alternative Names differ")
	}

	if !compareURISets(csr.URIs, cert.URIs) {
		return fmt.Errorf("URI Subject Alternative Names differ")
	}

	return nil
}

func compareStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aCopy := append([]string(nil), a...)
	bCopy := append([]string(nil), b...)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

func compareIPSets(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}

	aStr := make([]string, len(a))
	for i, ip := range a {
		aStr[i] = ip.String()
	}
	bStr := make([]string, len(b))
	for i, ip := range b {
		bStr[i] = ip.String()
	}

	return compareStringSets(aStr, bStr)
}

func compareURISets(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}

	aStr := make([]string, len(a))
	for i, u := range a {
		if u != nil {
			aStr[i] = u.String()
		}
	}
	bStr := make([]string, len(b))
	for i, u := range b {
		if u != nil {
			bStr[i] = u.String()
		}
	}

	return compareStringSets(aStr, bStr)
}
