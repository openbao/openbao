package logical

import (
	"net/textproto"
	reflect "reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/stretchr/testify/assert"
)

func TestValidateOperation(t *testing.T) {
	testCases := []struct {
		title   string
		input   []Operation
		wantErr bool
	}{
		{
			title:   "Single matching operation",
			input:   []Operation{ReadOperation},
			wantErr: false,
		},
		{
			title:   "Multiple matching operations",
			input:   []Operation{ReadOperation, PatchOperation},
			wantErr: false,
		},
		{
			title:   "Single non-matching operation",
			input:   []Operation{Operation("not-match")},
			wantErr: true,
		},
		{
			title:   "Multiple non-matching operations",
			input:   []Operation{ReadOperation, Operation("not-match")},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			err := ValidateOperation(tc.input...)
			if tc.wantErr {
				assert.Error(t, err, "expected error for ValidateOperation")
			} else {
				assert.NoError(t, err, "expected no error for ValidateOperation")
			}
		})
	}
}

func TestRequest_ParseMFAHandlers(t *testing.T) {
	var err error
	var expectedMFACreds MFACreds
	req := &Request{
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
	err = req.ParseMFAHeaders()
	if err != nil {
		t.Fatal(err)
	}

	// Verify that it is being parsed properly
	expectedMFACreds = MFACreds{
		"my_totp": []string{
			"123456",
			"111111",
		},
		"my_second_mfa": []string{
			"hi=hello",
		},
		"my_third_mfa": []string{},
	}
	if !reflect.DeepEqual(expectedMFACreds, req.MFACreds) {
		t.Fatalf("bad: parsed MFACreds; expected: %#v\n actual: %#v\n", expectedMFACreds, req.MFACreds)
	}

	// Split the creds of a method type in different headers and check if they
	// all get merged together
	req.Headers[headerName] = []string{
		"my_mfa:passcode=123456",
		"my_mfa:month=july",
		"my_mfa:day=tuesday",
	}
	err = req.ParseMFAHeaders()
	if err != nil {
		t.Fatal(err)
	}

	expectedMFACreds = MFACreds{
		"my_mfa": []string{
			"passcode=123456",
			"month=july",
			"day=tuesday",
		},
	}
	if !reflect.DeepEqual(expectedMFACreds, req.MFACreds) {
		t.Fatalf("bad: parsed MFACreds; expected: %#v\n actual: %#v\n", expectedMFACreds, req.MFACreds)
	}

	// Header without method name should error out
	req.Headers[headerName] = []string{
		":passcode=123456",
	}
	err = req.ParseMFAHeaders()
	if err == nil {
		t.Fatalf("expected an error; actual: %#v\n", req.MFACreds)
	}

	// Header without method name and method value should error out
	req.Headers[headerName] = []string{
		":",
	}
	err = req.ParseMFAHeaders()
	if err == nil {
		t.Fatalf("expected an error; actual: %#v\n", req.MFACreds)
	}

	// Header without method name and method value should error out
	req.Headers[headerName] = []string{
		"my_totp:",
	}
	err = req.ParseMFAHeaders()
	if err == nil {
		t.Fatalf("expected an error; actual: %#v\n", req.MFACreds)
	}
}
