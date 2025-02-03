// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathIssue(b *backend) *framework.Path {
	pattern := "issue/" + framework.GenericNameRegex("role")

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKI,
		OperationVerb:   "issue",
		OperationSuffix: "with-role",
	}

	return buildPathIssue(b, pattern, displayAttrs)
}

func pathCelIssue(b *backend) *framework.Path {
	fields := getCsrSignVerbatimSchemaFields()

	// Add key_bits and key_type fields
	fields["key_bits"] = &framework.FieldSchema{
		Type:    framework.TypeInt,
		Default: 0,
		Description: `The number of bits to use. Allowed values are
0 (universal default); with rsa key_type: 2048 (default), 3072, or
4096; with ec key_type: 224, 256 (default), 384, or 521; ignored with
ed25519.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: 0,
		},
	}

	fields["key_type"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "",
		Description: `The type of key to use; defaults to the empty string
to use whatever is specified by the role. "rsa", "ec", and "ed25519" are the
only valid values outside of the empty string.`,
		AllowedValues: []interface{}{"", "rsa", "ec", "ed25519"},
		DisplayAttrs: &framework.DisplayAttributes{
			Value: "",
		},
	}

	return &framework.Path{
		Pattern: "cel/issue/" + framework.GenericNameRegex("role"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixPKI,
			OperationVerb:   "issue",
			OperationSuffix: "with-cel-role",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCelIssue,
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"certificate": {
								Type:        framework.TypeString,
								Description: `Certificate`,
								Required:    true,
							},
							"issuing_ca": {
								Type:        framework.TypeString,
								Description: `Issuing Certificate Authority`,
								Required:    true,
							},
							"ca_chain": {
								Type:        framework.TypeCommaStringSlice,
								Description: `Certificate Chain`,
								Required:    false,
							},
							"serial_number": {
								Type:        framework.TypeString,
								Description: `Serial Number`,
								Required:    true,
							},
							"not_before": {
								Type:        framework.TypeInt64,
								Description: `Starting time of validity`,
								Required:    true,
							},
							"expiration": {
								Type:        framework.TypeInt64,
								Description: `Time of expiration`,
								Required:    true,
							},
							"private_key": {
								Type:        framework.TypeString,
								Description: `Private key`,
								Required:    false,
							},
							"private_key_type": {
								Type:        framework.TypeString,
								Description: `Private key type`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathCelIssueHelpSyn,
		HelpDescription: pathCelIssueHelpDesc,
	}
}

func pathIssuerIssue(b *backend) *framework.Path {
	pattern := "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/issue/" + framework.GenericNameRegex("role")

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKIIssuer,
		OperationVerb:   "issue",
		OperationSuffix: "with-role",
	}

	return buildPathIssue(b, pattern, displayAttrs)
}

func buildPathIssue(b *backend, pattern string, displayAttrs *framework.DisplayAttributes) *framework.Path {
	ret := &framework.Path{
		Pattern:      pattern,
		DisplayAttrs: displayAttrs,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.metricsWrap("issue", roleRequired, func(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error) {
					return b.pathIssue(ctx, req, data, role, false)
				}),
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"certificate": {
								Type:        framework.TypeString,
								Description: `Certificate`,
								Required:    true,
							},
							"issuing_ca": {
								Type:        framework.TypeString,
								Description: `Issuing Certificate Authority`,
								Required:    true,
							},
							"ca_chain": {
								Type:        framework.TypeCommaStringSlice,
								Description: `Certificate Chain`,
								Required:    false,
							},
							"serial_number": {
								Type:        framework.TypeString,
								Description: `Serial Number`,
								Required:    true,
							},
							"not_before": {
								Type:        framework.TypeInt64,
								Description: `Starting time of validity`,
								Required:    true,
							},
							"expiration": {
								Type:        framework.TypeInt64,
								Description: `Time of expiration`,
								Required:    true,
							},
							"private_key": {
								Type:        framework.TypeString,
								Description: `Private key`,
								Required:    false,
							},
							"private_key_type": {
								Type:        framework.TypeString,
								Description: `Private key type`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathIssueHelpSyn,
		HelpDescription: pathIssueHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})

	ret.Fields["key_bits"] = &framework.FieldSchema{
		Type:    framework.TypeInt,
		Default: 0,
		Description: `The number of bits to use. Allowed values are
0 (universal default); with rsa key_type: 2048 (default), 3072, or
4096; with ec key_type: 224, 256 (default), 384, or 521; ignored with
ed25519.`,
		DisplayAttrs: &framework.DisplayAttributes{
			Value: 0,
		},
	}

	ret.Fields["key_type"] = &framework.FieldSchema{
		Type:    framework.TypeString,
		Default: "",
		Description: `The type of key to use; defaults to the empty string
to use whatever is specified by the role. "rsa","ec", and "ed25519" are the
only valid values outside of the empty string.`,
		AllowedValues: []interface{}{"", "rsa", "ec", "ed25519"},
		DisplayAttrs: &framework.DisplayAttributes{
			Value: "",
		},
	}

	return ret
}

func pathSign(b *backend) *framework.Path {
	pattern := "sign/" + framework.GenericNameRegex("role")

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKI,
		OperationVerb:   "sign",
		OperationSuffix: "with-role",
	}

	return buildPathSign(b, pattern, displayAttrs)
}

func pathIssuerSign(b *backend) *framework.Path {
	pattern := "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/sign/" + framework.GenericNameRegex("role")

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKIIssuer,
		OperationVerb:   "sign",
		OperationSuffix: "with-role",
	}

	return buildPathSign(b, pattern, displayAttrs)
}

func buildPathSign(b *backend, pattern string, displayAttrs *framework.DisplayAttributes) *framework.Path {
	ret := &framework.Path{
		Pattern:      pattern,
		DisplayAttrs: displayAttrs,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.metricsWrap("sign", roleRequired, func(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error) {
					return b.pathSign(ctx, req, data, role)
				}),
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"certificate": {
								Type:        framework.TypeString,
								Description: `Certificate`,
								Required:    true,
							},
							"issuing_ca": {
								Type:        framework.TypeString,
								Description: `Issuing Certificate Authority`,
								Required:    true,
							},
							"ca_chain": {
								Type:        framework.TypeCommaStringSlice,
								Description: `Certificate Chain`,
								Required:    false,
							},
							"serial_number": {
								Type:        framework.TypeString,
								Description: `Serial Number`,
								Required:    true,
							},
							"not_before": {
								Type:        framework.TypeInt64,
								Description: `Starting time of validity`,
								Required:    true,
							},
							"expiration": {
								Type:        framework.TypeInt64,
								Description: `Time of expiration`,
								Required:    true,
							},
							"private_key": {
								Type:        framework.TypeString,
								Description: `Private key`,
								Required:    false,
							},
							"private_key_type": {
								Type:        framework.TypeString,
								Description: `Private key type`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}

	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})

	ret.Fields["csr"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Default:     "",
		Description: `PEM-format CSR to be signed.`,
	}

	return ret
}

func pathIssuerSignVerbatim(b *backend) *framework.Path {
	pattern := "issuer/" + framework.GenericNameRegex(issuerRefParam) + "/sign-verbatim" + framework.OptionalParamRegex("role")

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKIIssuer,
		OperationVerb:   "sign",
		OperationSuffix: "verbatim|verbatim-with-role",
	}

	return buildPathIssuerSignVerbatim(b, pattern, displayAttrs)
}

func pathSignVerbatim(b *backend) *framework.Path {
	pattern := "sign-verbatim" + framework.OptionalParamRegex("role")

	displayAttrs := &framework.DisplayAttributes{
		OperationPrefix: operationPrefixPKI,
		OperationVerb:   "sign",
		OperationSuffix: "verbatim|verbatim-with-role",
	}

	return buildPathIssuerSignVerbatim(b, pattern, displayAttrs)
}

func buildPathIssuerSignVerbatim(b *backend, pattern string, displayAttrs *framework.DisplayAttributes) *framework.Path {
	ret := &framework.Path{
		Pattern:      pattern,
		DisplayAttrs: displayAttrs,
		Fields:       getCsrSignVerbatimSchemaFields(),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.metricsWrap("sign-verbatim", roleRequired, func(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error) {
					return b.pathSignVerbatim(ctx, req, data, role)
				}),

				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: "OK",
						Fields: map[string]*framework.FieldSchema{
							"certificate": {
								Type:        framework.TypeString,
								Description: `Certificate`,
								Required:    true,
							},
							"issuing_ca": {
								Type:        framework.TypeString,
								Description: `Issuing Certificate Authority`,
								Required:    true,
							},
							"ca_chain": {
								Type:        framework.TypeCommaStringSlice,
								Description: `Certificate Chain`,
								Required:    false,
							},
							"serial_number": {
								Type:        framework.TypeString,
								Description: `Serial Number`,
								Required:    true,
							},
							"not_before": {
								Type:        framework.TypeInt64,
								Description: `Starting time of validity`,
								Required:    true,
							},
							"expiration": {
								Type:        framework.TypeInt64,
								Description: `Time of expiration`,
								Required:    true,
							},
							"private_key": {
								Type:        framework.TypeString,
								Description: `Private key`,
								Required:    false,
							},
							"private_key_type": {
								Type:        framework.TypeString,
								Description: `Private key type`,
								Required:    false,
							},
						},
					}},
				},
			},
		},

		HelpSynopsis:    pathIssuerSignVerbatimHelpSyn,
		HelpDescription: pathIssuerSignVerbatimHelpDesc,
	}

	return ret
}

const (
	pathIssuerSignVerbatimHelpSyn  = `Issue a certificate directly based on the provided CSR.`
	pathIssuerSignVerbatimHelpDesc = `
This API endpoint allows for directly signing the specified certificate
signing request (CSR) without the typical role-based validation. This
allows for attributes from the CSR to be directly copied to the resulting
certificate.

Usually the role-based sign operations (/sign and /issue) are preferred to
this operation.

Note that this is a very privileged operation and should be extremely
restricted in terms of who is allowed to use it. All values will be taken
directly from the incoming CSR. No further verification of attribute are
performed, except as permitted by this endpoint's parameters.

See the API documentation for more information about required parameters.
`
)

// pathIssue issues a certificate and private key from given parameters,
// subject to role restrictions
func (b *backend) pathIssue(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry, isCelRole bool) (*logical.Response, error) {
	keyTypeRaw, keyTypePresent := data.GetOk("key_type")
	keyBitsRaw, keyBitsPresent := data.GetOk("key_bits")

	// Allow overriding the role when it is explicitly any; this means the
	// operator didn't set limitations around the types of certificates
	// that could be issued (provided a CSR was given) and thus we can allow
	// anything.
	addWarning := false
	if role.KeyType == "any" {
		if !keyTypePresent {
			return logical.ErrorResponse("role key type \"any\" not allowed for issuing certificates without providing key_type and/or key_bits request parameters"), nil
		}

		role.KeyType = keyTypeRaw.(string)
		if keyBitsPresent {
			role.KeyBits = keyBitsRaw.(int)
		}

		// Perform validation of the new role parameters, updating an explicit
		// zero-valued KeyBits to a useful value.
		var err error
		role.KeyBits, role.SignatureBits, err = certutil.ValidateDefaultOrValueKeyTypeSignatureLength(role.KeyType, role.KeyBits, role.SignatureBits)
		if err != nil {
			return nil, fmt.Errorf("failed to validate role: %w", err)
		}
	} else if keyTypePresent || keyBitsPresent {
		addWarning = true
	}

	resp, err := b.pathIssueSignCert(ctx, req, data, role, false, false)
	if addWarning && resp != nil {
		resp.AddWarning("parameters key_type and key_bits ignored as role had specific values")
	}
	return resp, err
}

// pathCelIssue issues a certificate and private key from given parameters,
// subject to CEL role restrictions, and can modify the request based on CEL evaluations.
func (b *backend) pathCelIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Fetch the CEL role name from the request
	roleName := data.Get("role").(string)
	if roleName == "" {
		return nil, fmt.Errorf("missing CEL role name")
	}

	// Retrieve the CEL role
	celRole, err := b.getCelRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CEL role: %w", err)
	}
	if celRole == nil {
		return nil, fmt.Errorf("CEL role not found")
	}

	// Declare a map variable named "request" to represent the incoming data.
	envOptions := []celgo.EnvOption{
		celgo.Declarations(
			decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn)),
		),
	}

	// Add all variable declarations to the CEL environment.
	for _, variable := range celRole.ValidationProgram.Variables {
		envOptions = append(envOptions, celgo.Declarations(decls.NewVar(variable.Name, decls.Dyn)))
	}

	// Create the CEL environment using the prepared declarations.
	env, err := celgo.NewEnv(envOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Initialize the evaluation context for CEL expressions with the raw request data.
	// The "request" key allows CEL expressions to access and evaluate against input fields.
	// Additional variables and evaluated results will be added dynamically during processing.
	evaluationData := map[string]interface{}{
		"request": data.Raw,
	}

	// Evaluate all variables
	for _, variable := range celRole.ValidationProgram.Variables {
		result, err := parseCompileAndEvaluateVariable(env, variable, evaluationData)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		// Add the evaluated result for subsequent CEL evaluations.
		// This ensures variables can reference each other and build a cumulative evaluation context.
		evaluationData[variable.Name] = result.Value()
	}

	// Compile and evaluate the main CEL expression
	ast, issues := env.Parse(celRole.ValidationProgram.Expressions.Success)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL expression validation failed: %w", issues.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", err)
	}

	// Evaluate the success expression with the cumulative context
	evalResult, _, err := prog.Eval(evaluationData)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	// Ensure the evaluation result is a boolean
	if evalResult.Type() != celgo.BoolType {
		return nil, fmt.Errorf("CEL program did not return a boolean value for success")
	}

	// Check if CEL rules passed
	if !evalResult.Value().(bool) {
		return nil, fmt.Errorf("%s", celRole.ValidationProgram.Expressions.Error)
	}

	var generateLease bool
	genLeaseExpr := celRole.ValidationProgram.Expressions.GenerateLease
	if genLeaseExpr != "" {
		ast, issues := env.Parse(genLeaseExpr)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("failed to parse generate_lease CEL expression: %w", issues.Err())
		}

		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("failed to compile generate_lease CEL expression: %w", err)
		}

		// Evaluate generate_lease CEL Expression
		evalResult, _, err := prog.Eval(evaluationData)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate generate_lease CEL expression: %w", err)
		}

		// Ensure Boolean Result
		if evalResult.Type() != celgo.BoolType {
			return nil, fmt.Errorf("generate_lease expression did not return a boolean value")
		}
		generateLease = evalResult.Value().(bool)
	} else {
		generateLease = false // Default if not provided
	}

	var noStore bool
	noStoreExpr := celRole.ValidationProgram.Expressions.NoStore
	if noStoreExpr != "" {
		ast, issues := env.Parse(noStoreExpr)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("failed to parse no_store CEL expression: %w", issues.Err())
		}

		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("failed to compile no_store CEL expression: %w", err)
		}

		// Evaluate no_store CEL Expression
		evalResult, _, err := prog.Eval(evaluationData)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate no_store CEL expression: %w", err)
		}

		// Ensure Boolean Result
		if evalResult.Type() != celgo.BoolType {
			return nil, fmt.Errorf("no_store expression did not return a boolean value")
		}
		noStore = evalResult.Value().(bool)
	} else {
		noStore = false // Default if not provided
	}

	// Fetch issuer information
	var issuerName string
	if strings.HasPrefix(req.Path, "cel/issue/") {
		issuerName = celRole.ValidationProgram.Expressions.Issuer
		if len(issuerName) == 0 {
			issuerName = defaultRef
		}
	} else {
		// Otherwise, we must have a newer API which requires an issuer
		// reference. Fetch it in this case
		issuerName = getIssuerRef(data)
		if len(issuerName) == 0 {
			return logical.ErrorResponse("missing issuer reference"), nil
		}
	}

	var caErr error
	sc := b.makeStorageContext(ctx, req.Storage)
	signingBundle, caErr := sc.fetchCAInfo(issuerName, IssuanceUsage)
	if caErr != nil {
		switch caErr.(type) {
		case errutil.UserError:
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"could not fetch the CA certificate (was one set?): %s", caErr)}
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf(
				"error fetching CA certificate: %s", caErr)}
		}
	}

	_, ok := data.GetOk("key_type")
	if !ok {
		// Default to RSA
		data.Raw["key_type"] = "rsa"
	}
	_, ok = data.GetOk("key_bits")
	if !ok {
		// Default to 2048 bits
		data.Raw["key_bits"] = 2048
	}

	parsedBundle, warnings, err := generateBasicCert(sc, data, signingBundle, false, rand.Reader)

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw signing bundle to cert bundle: %w", err)
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw cert bundle to cert bundle: %w", err)
	}

	caChainGen := newCaChainOutput(parsedBundle, data)

	respData := map[string]interface{}{
		"certificate":      cb.Certificate,
		"not_before":       int64(parsedBundle.Certificate.NotBefore.Unix()),
		"expiration":       int64(parsedBundle.Certificate.NotAfter.Unix()),
		"serial_number":    cb.SerialNumber,
		"issuing_ca":       signingCB.Certificate,
		"private_key":      cb.PrivateKey,
		"private_key_type": cb.PrivateKeyType,
	}

	if caChainGen.containsChain() {
		respData["ca_chain"] = caChainGen.pemEncodedChain()
	}

	// Generate Response
	var resp *logical.Response
	if generateLease {
		// Lease-Managed Certificate
		resp = b.Secret(SecretCertsType).Response(
			respData,
			map[string]interface{}{
				"serial_number": cb.SerialNumber,
			})
		resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())
	} else {
		// Non-Leased Certificate
		resp = &logical.Response{
			Data: respData,
		}
	}

	if !noStore {
		key := "certs/" + normalizeSerial(cb.SerialNumber)
		certsCounted := b.certsCounted.Load()
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   key,
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to store certificate locally: %w", err)
		}
		b.ifCountEnabledIncrementTotalCertificatesCount(certsCounted, key)
	}

	if data.Get("private_key_format").(string) == "pkcs8" {
		err = convertRespToPKCS8(resp)
		if err != nil {
			return nil, err
		}
	}

	resp = addWarnings(resp, warnings)

	return resp, nil
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error) {
	return b.pathIssueSignCert(ctx, req, data, role, true, false)
}

// pathSignVerbatim issues a certificate from a submitted CSR, *not* subject to
// role restrictions
func (b *backend) pathSignVerbatim(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry) (*logical.Response, error) {
	entry := buildSignVerbatimRole(data, role)

	return b.pathIssueSignCert(ctx, req, data, entry, true, true)
}

func (b *backend) pathIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry, useCSR, useCSRValues bool) (*logical.Response, error) {
	// If storing the certificate and on a performance standby, forward this request on to the primary
	// Allow performance secondaries to generate and store certificates locally to them.
	if !role.NoStore && b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby) {
		return nil, logical.ErrReadOnly
	}

	// We prefer the issuer from the role in two cases:
	//
	// 1. On the legacy sign-verbatim paths, as we always provision an issuer
	//    in both the role and role-less cases, and
	// 2. On the legacy sign/:role or issue/:role paths, as the issuer was
	//    set on the role directly (either via upgrade or not). Note that
	//    the updated issuer/:ref/{sign,issue}/:role path is not affected,
	//    and we instead pull the issuer out of the path instead (which
	//    allows users with access to those paths to manually choose their
	//    issuer in desired scenarios).
	var issuerName string
	if strings.HasPrefix(req.Path, "sign-verbatim/") || strings.HasPrefix(req.Path, "sign/") || strings.HasPrefix(req.Path, "issue/") || strings.HasPrefix(req.Path, "cel/issue/") {
		issuerName = role.Issuer
		if len(issuerName) == 0 {
			issuerName = defaultRef
		}
	} else {
		// Otherwise, we must have a newer API which requires an issuer
		// reference. Fetch it in this case
		issuerName = getIssuerRef(data)
		if len(issuerName) == 0 {
			return logical.ErrorResponse("missing issuer reference"), nil
		}
	}

	format := getFormat(data)
	if format == "" {
		return logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", or "pem_bundle"`), nil
	}

	var caErr error
	sc := b.makeStorageContext(ctx, req.Storage)
	signingBundle, caErr := sc.fetchCAInfo(issuerName, IssuanceUsage)
	if caErr != nil {
		switch caErr.(type) {
		case errutil.UserError:
			return nil, errutil.UserError{Err: fmt.Sprintf(
				"could not fetch the CA certificate (was one set?): %s", caErr)}
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf(
				"error fetching CA certificate: %s", caErr)}
		}
	}

	input := &inputBundle{
		req:     req,
		apiData: data,
		role:    role,
	}
	var parsedBundle *certutil.ParsedCertBundle
	var err error
	var warnings []string
	if useCSR {
		parsedBundle, warnings, err = signCert(b, input, signingBundle, false, useCSRValues)
	} else {
		parsedBundle, warnings, err = generateCert(sc, input, signingBundle, false, rand.Reader)
	}
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		default:
			return nil, fmt.Errorf("error signing/generating certificate: %w", err)
		}
	}

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw signing bundle to cert bundle: %w", err)
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw cert bundle to cert bundle: %w", err)
	}

	caChainGen := newCaChainOutput(parsedBundle, data)

	respData := map[string]interface{}{
		"not_before":    int64(parsedBundle.Certificate.NotBefore.Unix()),
		"expiration":    int64(parsedBundle.Certificate.NotAfter.Unix()),
		"serial_number": cb.SerialNumber,
	}

	switch format {
	case "pem":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.Certificate
		if caChainGen.containsChain() {
			respData["ca_chain"] = caChainGen.pemEncodedChain()
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "pem_bundle":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.ToPEMBundle()
		if caChainGen.containsChain() {
			respData["ca_chain"] = caChainGen.pemEncodedChain()
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "der":
		respData["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		respData["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)

		if caChainGen.containsChain() {
			respData["ca_chain"] = caChainGen.derEncodedChain()
		}

		if !useCSR {
			respData["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
			respData["private_key_type"] = cb.PrivateKeyType
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	var resp *logical.Response
	switch {
	case role.GenerateLease == nil:
		return nil, fmt.Errorf("generate lease in role is nil")
	case !*role.GenerateLease:
		// If lease generation is disabled do not populate `Secret` field in
		// the response
		resp = &logical.Response{
			Data: respData,
		}
	default:
		resp = b.Secret(SecretCertsType).Response(
			respData,
			map[string]interface{}{
				"serial_number": cb.SerialNumber,
			})
		resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())
	}

	if data.Get("private_key_format").(string) == "pkcs8" {
		err = convertRespToPKCS8(resp)
		if err != nil {
			return nil, err
		}
	}

	if !role.NoStore {
		key := "certs/" + normalizeSerial(cb.SerialNumber)
		certsCounted := b.certsCounted.Load()
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   key,
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to store certificate locally: %w", err)
		}
		b.ifCountEnabledIncrementTotalCertificatesCount(certsCounted, key)
	}

	if useCSR {
		if role.UseCSRCommonName && data.Get("common_name").(string) != "" {
			resp.AddWarning("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true")
		}
		if role.UseCSRSANs && data.Get("alt_names").(string) != "" {
			resp.AddWarning("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true")
		}
	}

	resp = addWarnings(resp, warnings)

	return resp, nil
}

type caChainOutput struct {
	chain []*certutil.CertBlock
}

func newCaChainOutput(parsedBundle *certutil.ParsedCertBundle, data *framework.FieldData) caChainOutput {
	if filterCaChain := data.Get("remove_roots_from_chain").(bool); filterCaChain {
		var myChain []*certutil.CertBlock
		for _, certBlock := range parsedBundle.CAChain {
			cert := certBlock.Certificate

			if (len(cert.AuthorityKeyId) > 0 && !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId)) ||
				(len(cert.AuthorityKeyId) == 0 && (!bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignatureFrom(cert) != nil)) {
				// We aren't self-signed so add it to the list.
				myChain = append(myChain, certBlock)
			}
		}
		return caChainOutput{chain: myChain}
	}

	return caChainOutput{chain: parsedBundle.CAChain}
}

func (cac *caChainOutput) containsChain() bool {
	return len(cac.chain) > 0
}

func (cac *caChainOutput) pemEncodedChain() []string {
	var chain []string
	for _, cert := range cac.chain {
		block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Bytes}
		certificate := strings.TrimSpace(string(pem.EncodeToMemory(&block)))
		chain = append(chain, certificate)
	}
	return chain
}

func (cac *caChainOutput) derEncodedChain() []string {
	var derCaChain []string
	for _, caCert := range cac.chain {
		derCaChain = append(derCaChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
	}
	return derCaChain
}

const pathIssueHelpSyn = `
Request a certificate using a certain role with the provided details.
`

const pathIssueHelpDesc = `
This path allows requesting a certificate to be issued according to the
policy of the given role. The certificate will only be issued if the
requested details are allowed by the role policy.

This path returns a certificate and a private key. If you want a workflow
that does not expose a private key, generate a CSR locally and use the
sign path instead.
`

const pathCelIssueHelpSyn = `
Request a certificate using a certain cel role with the provided details.
`

const pathCelIssueHelpDesc = `
This path allows requesting a certificate to be issued according to the
policy of the given cel role. The certificate will only be issued if the
requested details are allowed by the cel role policy.

This path returns a certificate and a private key. If you want a workflow
that does not expose a private key, generate a CSR locally and use the
cel/sign path instead.
`

const pathSignHelpSyn = `
Request certificates using a certain role with the provided details.
`

const pathSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given role. The certificate will only be issued if the
requested common name is allowed by the role policy.

This path requires a CSR; if you want OpenBao to generate a private key
for you, use the issue path instead.
`

const pathCelSignHelpSyn = `
Request certificates using a certain CEL role with the provided details.
`

const pathCelSignHelpDesc = `
This path allows requesting certificates to be issued according to the
policy of the given CEL role. The certificate will only be issued if the
requested common name is allowed by the role policy.

This path requires a CSR; if you want OpenBao to generate a private key
for you, use the issue path instead.
`
