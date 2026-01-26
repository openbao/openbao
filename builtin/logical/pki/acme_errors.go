// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Error prefix; see RFC 8555 Section 6.7. Errors.
const (
	ErrorPrefix      = "urn:ietf:params:acme:error:"
	ErrorContentType = "application/problem+json"
)

// See RFC 8555 Section 6.7. Errors.
var ErrAccountDoesNotExist = errors.New("the request specified an account that does not exist")

var ErrAcmeDisabled = errors.New("ACME feature is disabled")

var (
	ErrAlreadyRevoked        = errors.New("the request specified a certificate to be revoked that has already been revoked")
	ErrBadCSR                = errors.New("the CSR is unacceptable")
	ErrBadNonce              = errors.New("the client sent an unacceptable anti-replay nonce")
	ErrBadPublicKey          = errors.New("the JWS was signed by a public key the server does not support")
	ErrBadRevocationReason   = errors.New("the revocation reason provided is not allowed by the server")
	ErrBadSignatureAlgorithm = errors.New("the JWS was signed with an algorithm the server does not support")
	//nolint:staticcheck //CAA is a proper noun
	ErrCAA                     = errors.New("Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate")
	ErrCompound                = errors.New("specific error conditions are indicated in the 'subproblems' array")
	ErrConnection              = errors.New("the server could not connect to validation target")
	ErrDNS                     = errors.New("there was a problem with a DNS query during identifier validation")
	ErrExternalAccountRequired = errors.New("the request must include a value for the 'externalAccountBinding' field")
	ErrIncorrectResponse       = errors.New("response received didn't match the challenge's requirements")
	ErrInvalidContact          = errors.New("a contact URL for an account was invalid")
	ErrMalformed               = errors.New("the request message was malformed")
	ErrOrderNotReady           = errors.New("the request attempted to finalize an order that is not ready to be finalized")
	ErrRateLimited             = errors.New("the request exceeds a rate limit")
	ErrRejectedIdentifier      = errors.New("the server will not issue certificates for the identifier")
	ErrServerInternal          = errors.New("the server experienced an internal error")
	ErrTLS                     = errors.New("the server received a TLS error during validation")
	ErrUnauthorized            = errors.New("the client lacks sufficient authorization")
	ErrUnsupportedContact      = errors.New("a contact URL for an account used an unsupported protocol scheme")
	ErrUnsupportedIdentifier   = errors.New("an identifier is of an unsupported type")
	ErrUserActionRequired      = errors.New("visit the 'instance' URL and take actions specified there")
)

// Mapping of err->name; see table in RFC 8555 Section 6.7. Errors.
var errIdMappings = map[error]string{
	ErrAccountDoesNotExist:     "accountDoesNotExist",
	ErrAlreadyRevoked:          "alreadyRevoked",
	ErrBadCSR:                  "badCSR",
	ErrBadNonce:                "badNonce",
	ErrBadPublicKey:            "badPublicKey",
	ErrBadRevocationReason:     "badRevocationReason",
	ErrBadSignatureAlgorithm:   "badSignatureAlgorithm",
	ErrCAA:                     "caa",
	ErrCompound:                "compound",
	ErrConnection:              "connection",
	ErrDNS:                     "dns",
	ErrExternalAccountRequired: "externalAccountRequired",
	ErrIncorrectResponse:       "incorrectResponse",
	ErrInvalidContact:          "invalidContact",
	ErrMalformed:               "malformed",
	ErrOrderNotReady:           "orderNotReady",
	ErrRateLimited:             "rateLimited",
	ErrRejectedIdentifier:      "rejectedIdentifier",
	ErrServerInternal:          "serverInternal",
	ErrTLS:                     "tls",
	ErrUnauthorized:            "unauthorized",
	ErrUnsupportedContact:      "unsupportedContact",
	ErrUnsupportedIdentifier:   "unsupportedIdentifier",
	ErrUserActionRequired:      "userActionRequired",
}

// Mapping of err->status codes; see table in RFC 8555 Section 6.7. Errors.
var errCodeMappings = map[error]int{
	ErrAccountDoesNotExist:     http.StatusBadRequest, // See RFC 8555 Section 7.3.1. Finding an Account URL Given a Key.
	ErrAlreadyRevoked:          http.StatusBadRequest,
	ErrBadCSR:                  http.StatusBadRequest,
	ErrBadNonce:                http.StatusBadRequest,
	ErrBadPublicKey:            http.StatusBadRequest,
	ErrBadRevocationReason:     http.StatusBadRequest,
	ErrBadSignatureAlgorithm:   http.StatusBadRequest,
	ErrCAA:                     http.StatusForbidden,
	ErrCompound:                http.StatusBadRequest,
	ErrConnection:              http.StatusInternalServerError,
	ErrDNS:                     http.StatusInternalServerError,
	ErrExternalAccountRequired: http.StatusUnauthorized,
	ErrIncorrectResponse:       http.StatusBadRequest,
	ErrInvalidContact:          http.StatusBadRequest,
	ErrMalformed:               http.StatusBadRequest,
	ErrOrderNotReady:           http.StatusForbidden, // See RFC 8555 Section 7.4. Applying for Certificate Issuance.
	ErrRateLimited:             http.StatusTooManyRequests,
	ErrRejectedIdentifier:      http.StatusBadRequest,
	ErrServerInternal:          http.StatusInternalServerError,
	ErrTLS:                     http.StatusInternalServerError,
	ErrUnauthorized:            http.StatusUnauthorized,
	ErrUnsupportedContact:      http.StatusBadRequest,
	ErrUnsupportedIdentifier:   http.StatusBadRequest,
	ErrUserActionRequired:      http.StatusUnauthorized,
}

type ErrorResponse struct {
	StatusCode  int              `json:"-"`
	Type        string           `json:"type"`
	Detail      string           `json:"detail"`
	Subproblems []*ErrorResponse `json:"subproblems,omitempty"`
}

func (e *ErrorResponse) MarshalForStorage() map[string]interface{} {
	subProblems := []map[string]interface{}{}
	for _, subProblem := range e.Subproblems {
		subProblems = append(subProblems, subProblem.MarshalForStorage())
	}
	return map[string]interface{}{
		"status":      e.StatusCode,
		"type":        e.Type,
		"detail":      e.Detail,
		"subproblems": subProblems,
	}
}

func (e *ErrorResponse) Marshal() (*logical.Response, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling of error response: %w", err)
	}

	var resp logical.Response
	resp.Data = map[string]interface{}{
		logical.HTTPContentType: ErrorContentType,
		logical.HTTPRawBody:     body,
		logical.HTTPStatusCode:  e.StatusCode,
	}

	return &resp, nil
}

func FindType(given error) (id string, code int, found bool, err error) {
	matchedError := false
	for err, id = range errIdMappings {
		if errors.Is(given, err) {
			matchedError = true
			break
		}
	}

	// If the given error was not matched from one of the standard ACME errors
	// make this error, force ErrServerInternal
	if !matchedError {
		err = ErrServerInternal
		id = errIdMappings[err]
	}

	code = errCodeMappings[err]

	return id, code, found, err
}

func TranslateError(given error) (*logical.Response, error) {
	if errors.Is(given, logical.ErrReadOnly) {
		return nil, given
	}

	if errors.Is(given, ErrAcmeDisabled) {
		return logical.RespondWithStatusCode(nil, nil, http.StatusNotFound)
	}

	body := TranslateErrorToErrorResponse(given)

	return body.Marshal()
}

func TranslateErrorToErrorResponse(given error) ErrorResponse {
	// We're multierror aware here: if we're given a list of errors, assume
	// they're structured so the first error is the outer error and the inner
	// subproblems are subsequent in the multierror.
	var remaining []error
	if unwrapped, ok := given.(*multierror.Error); ok {
		remaining = unwrapped.Errors[1:]
		given = unwrapped.Errors[0]
	}

	id, code, found, _ := FindType(given)
	if !found && len(remaining) > 0 {
		// Translate multierrors into a generic error code.
		id = errIdMappings[ErrCompound]
		code = errCodeMappings[ErrCompound]
	}

	var body ErrorResponse
	body.Type = ErrorPrefix + id
	body.Detail = given.Error()
	body.StatusCode = code

	for _, subgiven := range remaining {
		subid, _, _, _ := FindType(subgiven)

		var sub ErrorResponse
		sub.Type = ErrorPrefix + subid
		body.Detail = subgiven.Error()

		body.Subproblems = append(body.Subproblems, &sub)
	}
	return body
}
