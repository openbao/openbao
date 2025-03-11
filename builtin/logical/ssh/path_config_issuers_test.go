package ssh

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestSSH_ConfigIssuers(t *testing.T) {
	b, s := CreateBackendWithStorage(t)

	// reading the default issuer when no default has been configured should return a 400 error
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/issuers",
		Storage:   s,
	})
	require.NoError(t, err, "unexpected error reading issuers config")
	require.True(t, resp != nil && resp.IsError(), "expected error response when no default issuer is configured")

	// create an issuer and set it as default
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Storage:   s,
		Data: map[string]interface{}{
			"generate_signing_key": true,
		},
	})
	require.NoError(t, err, "cannot submit issuer")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response submitting issuer")

	// parse default issuer's id
	defaultIssuerId := resp.Data["issuer_id"]

	// read issuer's config and check if the default issuer is set
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/issuers",
		Storage:   s,
	})
	require.NoError(t, err, "cannot read issuer's config")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response reading issuer's config")

	// check if the 'default' keyword exists and the value is the same as the default issuer's id
	require.Equal(t, defaultIssuerId, resp.Data["default"], "default issuer ID mismatch")

	// create a new issuer
	issuerName := "test-issuer"
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuers/import/" + issuerName,
		Storage:   s,
	})
	require.NoError(t, err, "cannot create new issuer")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response creating new issuer")

	// parse 'test-issuer's id
	testIssuerId := resp.Data["issuer_id"]

	// set 'test-issuer' as the default issuer
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/issuers",
		Data: map[string]interface{}{
			"default": issuerName,
		},
		Storage: s,
	})
	require.NoError(t, err, "cannot set 'test-issuer' as default")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response setting test-issuer as default")

	// read the 'default' issuer and check if it's the same as 'test-issuer'
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/issuers",
		Storage:   s,
	})
	require.NoError(t, err, "cannot read default issuer")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response reading default issuer")

	require.Equal(t, testIssuerId, resp.Data["default"], "default issuer ID mismatch after update")

	// update issuer's config with the default being directly the issuer's id
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/issuers",
		Data: map[string]interface{}{
			"default": testIssuerId,
		},
		Storage: s,
	})
	require.NoError(t, err, "cannot update issuer's config")
	require.False(t, resp != nil && resp.IsError(), "unexpected error response updating issuer's config")

	require.Equal(t, testIssuerId, resp.Data["default"], "default issuer ID mismatch after update")

	// try to set the keyword `default` as the default issuer should expect an error
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/issuers",
		Data: map[string]interface{}{
			"default": "default",
		},
	})
	require.NoError(t, err, "unexpected error when setting 'default' as the default issuer")
	require.True(t, resp != nil && resp.IsError(), "expected error response when setting 'default' as the default issuer")

	// try to set an empty string as the default issuer should expect an error
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/issuers",
		Data: map[string]interface{}{
			"default": "",
		},
	})
	require.NoError(t, err, "unexpected error when setting an empty string as the default issuer")
	require.True(t, resp != nil && resp.IsError(), "expected error response when setting an empty string as the default issuer")
}
