// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResponseUtil_RespondErrorCommon_basic(t *testing.T) {
	testCases := []struct {
		title          string
		req            *Request
		resp           *Response
		respErr        error
		expectedStatus int
		expectedErr    error
	}{
		{
			title:          "Throttled, no error",
			respErr:        ErrUpstreamRateLimited,
			resp:           &Response{},
			expectedStatus: 502,
		},
		{
			title:   "Throttled, with error",
			respErr: ErrUpstreamRateLimited,
			resp: &Response{
				Data: map[string]interface{}{
					"error": "rate limited",
				},
			},
			expectedStatus: 502,
		},
		{
			title: "Read not found",
			req: &Request{
				Operation: ReadOperation,
			},
			respErr:        nil,
			expectedStatus: 404,
		},
		{
			title: "Header not found",
			req: &Request{
				Operation: HeaderOperation,
			},
			respErr:        nil,
			expectedStatus: 404,
		},
		{
			title: "List with response and no keys",
			req: &Request{
				Operation: ListOperation,
			},
			resp:           &Response{},
			respErr:        nil,
			expectedStatus: 404,
		},
		{
			title: "List with response and keys",
			req: &Request{
				Operation: ListOperation,
			},
			resp: &Response{
				Data: map[string]interface{}{
					"keys": []string{"some", "things", "here"},
				},
			},
			respErr:        nil,
			expectedStatus: 0,
		},
		{
			title:   "Invalid Credentials error ",
			respErr: ErrInvalidCredentials,
			resp: &Response{
				Data: map[string]interface{}{
					"error": "error due to wrong credentials",
				},
			},
			expectedErr:    errors.New("error due to wrong credentials"),
			expectedStatus: 400,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			var respErr error
			if tc.respErr != nil {
				respErr = tc.respErr
			}
			status, err := RespondErrorCommon(tc.req, tc.resp, respErr)
			require.Equal(t, tc.expectedStatus, status)
			if tc.expectedErr != nil {
				require.Contains(t, tc.expectedErr.Error(), err.Error())
			}
		})
	}
}
