// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//go:build !blackbox

package http

import (
	"net/http"
	"net/textproto"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/internal/assert"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
)

const (
	EMPTY = ""
)

func TestHandler_parseMFAHandler(t *testing.T) {
	var err error
	var expectedMFACreds logical.MFACreds
	req := &logical.Request{
		Headers: make(map[string][]string),
	}

	headerName := textproto.CanonicalMIMEHeaderKey(consts.MFAHeaderName)

	// Set TOTP passcode in the MFA header
	req.Headers[headerName] = []string{
		"my_totp:123456",
		"my_totp:111111",
		"my_second_mfa:hi=hello",
		"my_third_mfa",
	}
	err = parseMFAHeader(req)
	assert.Ok(t, err)

	// Verify that it is being parsed properly
	expectedMFACreds = logical.MFACreds{
		"my_totp": []string{
			"123456",
			"111111",
		},
		"my_second_mfa": []string{
			"hi=hello",
		},
		"my_third_mfa": []string{},
	}
	assert.Equal(t, req.MFACreds, expectedMFACreds)

	// Split the creds of a method type in different headers and check if they
	// all get merged together
	req.Headers[headerName] = []string{
		"my_mfa:passcode=123456",
		"my_mfa:month=july",
		"my_mfa:day=tuesday",
	}
	err = parseMFAHeader(req)
	assert.Ok(t, err)

	expectedMFACreds = logical.MFACreds{
		"my_mfa": []string{
			"passcode=123456",
			"month=july",
			"day=tuesday",
		},
	}
	assert.Equal(t, req.MFACreds, expectedMFACreds)

	// Header without method name should error out
	req.Headers[headerName] = []string{
		":passcode=123456",
	}
	err = parseMFAHeader(req)
	assert.DesiredError(t, err, req.MFACreds)

	// Header without method name and method value should error out
	req.Headers[headerName] = []string{
		":",
	}
	err = parseMFAHeader(req)
	assert.DesiredError(t, err, req.MFACreds)

	// Header without method name and method value should error out
	req.Headers[headerName] = []string{
		"my_totp:",
	}
	err = parseMFAHeader(req)
	assert.DesiredError(t, err, req.MFACreds)
}

func TestHandler_requestAuth(t *testing.T) {
	core, _, token := vault.TestCoreUnsealed(t)

	rootCtx := namespace.RootContext(t.Context())
	te, err := core.LookupToken(rootCtx, token)
	assert.Ok(t, err)

	rWithAuthorization, err := http.NewRequest("GET", "v1/test/path", nil)
	assert.Ok(t, err)
	rWithAuthorization.Header.Set("Authorization", "Bearer "+token)

	rWithVault, err := http.NewRequest("GET", "v1/test/path", nil)
	assert.Ok(t, err)
	rWithVault.Header.Set(consts.AuthHeaderName, token)

	for _, r := range []*http.Request{rWithVault, rWithAuthorization} {
		req := logical.TestRequest(t, logical.ReadOperation, "test/path")
		r = r.WithContext(rootCtx)
		requestAuth(r, req)
		err = core.PopulateTokenEntry(rootCtx, req)
		assert.Ok(t, err)

		assert.Equal(t, req.ClientToken, token)
		assert.NotNil(t, req.TokenEntry())
		assert.Equal(t, req.TokenEntry(), te)
		assert.NotEqual(t, req.ClientTokenAccessor, EMPTY)
	}

	rNothing, err := http.NewRequest("GET", "v1/test/path", nil)
	assert.Ok(t, err)
	req := logical.TestRequest(t, logical.ReadOperation, "test/path")

	requestAuth(rNothing, req)
	err = core.PopulateTokenEntry(rootCtx, req)
	assert.Ok(t, err)
	assert.Equal(t, req.ClientToken, EMPTY)
}

func TestHandler_getTokenFromReq(t *testing.T) {
	r := http.Request{Header: http.Header{}}

	tok, _ := getTokenFromReq(&r)
	assert.Equal(t, tok, EMPTY)

	r.Header.Set("Authorization", "Bearer TOKEN NOT_GOOD_TOKEN")
	token, fromHeader := getTokenFromReq(&r)
	assert.Equal(t, fromHeader, true)
	assert.Equal(t, token, "TOKEN NOT_GOOD_TOKEN")
	assert.NotEqual(t, r.Header.Get("Authorization"), EMPTY)

	r.Header.Set(consts.AuthHeaderName, "NEWTOKEN")
	tok, _ = getTokenFromReq(&r)
	assert.NotEqual(t, tok, "TOKEN")
	assert.Equal(t, tok, "NEWTOKEN")

	r.Header = http.Header{}
	r.Header.Set("Authorization", "Basic TOKEN")
	tok, fromHeader = getTokenFromReq(&r)
	assert.Equal(t, tok, EMPTY)
	assert.Equal(t, fromHeader, false)
}
