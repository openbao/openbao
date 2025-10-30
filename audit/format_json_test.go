// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestFormatJSON_formatRequest(t *testing.T) {
	salter, err := salt.NewSalt(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	saltFunc := func(context.Context) (*salt.Salt, error) {
		return salter, nil
	}

	expectedResultStr := fmt.Sprintf(testFormatJSONReqBasicStrFmt, salter.GetIdentifiedHMAC("foo"))

	issueTime, _ := time.Parse(time.RFC3339, "2020-05-28T13:40:18-05:00")
	cases := map[string]struct {
		Auth        *logical.Auth
		Req         *logical.Request
		Err         error
		Prefix      string
		ExpectedStr string
	}{
		"auth, request": {
			&logical.Auth{
				ClientToken:     "foo",
				Accessor:        "bar",
				DisplayName:     "testtoken",
				EntityID:        "foobarentity",
				NoDefaultPolicy: true,
				Policies:        []string{"root"},
				TokenType:       logical.TokenTypeService,
				LeaseOptions: logical.LeaseOptions{
					TTL:       time.Hour * 4,
					IssueTime: issueTime,
				},
			},
			&logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "/foo",
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
				WrapInfo: &logical.RequestWrapInfo{
					TTL: 60 * time.Second,
				},
				Headers: map[string][]string{
					"foo": {"bar"},
				},
			},
			errors.New("this is an error"),
			"",
			expectedResultStr,
		},
		"auth, request with prefix": {
			&logical.Auth{
				ClientToken:     "foo",
				Accessor:        "bar",
				EntityID:        "foobarentity",
				DisplayName:     "testtoken",
				NoDefaultPolicy: true,
				Policies:        []string{"root"},
				TokenType:       logical.TokenTypeService,
				LeaseOptions: logical.LeaseOptions{
					TTL:       time.Hour * 4,
					IssueTime: issueTime,
				},
			},
			&logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "/foo",
				Connection: &logical.Connection{
					RemoteAddr: "127.0.0.1",
				},
				WrapInfo: &logical.RequestWrapInfo{
					TTL: 60 * time.Second,
				},
				Headers: map[string][]string{
					"foo": {"bar"},
				},
			},
			errors.New("this is an error"),
			"@cee: ",
			expectedResultStr,
		},
	}

	for name, tc := range cases {
		var buf bytes.Buffer
		formatter := AuditFormatter{
			AuditFormatWriter: &JSONFormatWriter{
				Prefix:   tc.Prefix,
				SaltFunc: saltFunc,
			},
		}
		config := FormatterConfig{
			HMACAccessor: false,
		}
		in := &logical.LogInput{
			Auth:     tc.Auth,
			Request:  tc.Req,
			OuterErr: tc.Err,
		}
		if err := formatter.FormatRequest(namespace.RootContext(nil), &buf, config, in); err != nil {
			t.Fatalf("bad: %s\nerr: %s", name, err)
		}

		if !strings.HasPrefix(buf.String(), tc.Prefix) {
			t.Fatalf("no prefix: %s \n log: %s\nprefix: %s", name, expectedResultStr, tc.Prefix)
		}

		expectedjson := new(AuditRequestEntry)

		if err := jsonutil.DecodeJSON([]byte(expectedResultStr), &expectedjson); err != nil {
			t.Fatalf("bad json: %s", err)
		}
		expectedjson.Request.Namespace = &AuditNamespace{ID: "root"}

		actualjson := new(AuditRequestEntry)
		if err := jsonutil.DecodeJSON(buf.Bytes()[len(tc.Prefix):], &actualjson); err != nil {
			t.Fatalf("bad json: %s", err)
		}

		expectedjson.Time = actualjson.Time

		expectedBytes, err := json.Marshal(expectedjson)
		if err != nil {
			t.Fatalf("unable to marshal json: %s", err)
		}

		if !strings.HasSuffix(strings.TrimSpace(buf.String()), string(expectedBytes)) {
			t.Fatalf(
				"bad: %s\nResult:\n\n%q\n\nExpected:\n\n%q",
				name, buf.String(), string(expectedBytes))
		}
	}
}

const testFormatJSONReqBasicStrFmt = `{"time":"2015-08-05T13:45:46Z","type":"request","auth":{"client_token":"%s","accessor":"bar","display_name":"testtoken","policies":["root"],"no_default_policy":true,"metadata":null,"entity_id":"foobarentity","token_type":"service", "token_ttl": 14400, "token_issue_time": "2020-05-28T13:40:18-05:00"},"request":{"operation":"update","path":"/foo","data":null,"wrap_ttl":60,"remote_address":"127.0.0.1","headers":{"foo":["bar"]}},"error":"this is an error"}
`
