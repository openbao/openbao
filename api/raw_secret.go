// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// RawSecret is a Secret whose string values are returned as []byte, so that
// callers can overwrite them after use. Go strings are immutable and cannot
// be erased.
//
// Erasing the returned slices does not remove copies held elsewhere, such as
// in the buffers of net/http, crypto/tls or encoding/json.
type RawSecret struct {
	// The request ID that generated this response
	RequestID string

	LeaseID       string
	LeaseDuration int
	Renewable     bool

	// Data is the actual contents of the secret, with string values
	// represented as []byte.
	Data map[string]any

	// Warnings contains any warnings related to the operation. These
	// are not issues that caused the command to fail, but that the
	// client should be aware of.
	Warnings []string

	// Auth, if non-nil, means that there was authentication information
	// attached to this response.
	Auth *SecretAuth

	// WrapInfo, if non-nil, means that the initial response was wrapped in the
	// cubbyhole of the given token (which has a TTL of the given number of
	// seconds)
	WrapInfo *SecretWrapInfo
}

// rawSecretWire keeps Data as raw JSON so that string values are not decoded
// into Go strings.
type rawSecretWire struct {
	RequestID string `json:"request_id"`

	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`

	Data map[string]json.RawMessage `json:"data"`

	Warnings []string `json:"warnings"`

	Auth *SecretAuth `json:"auth,omitempty"`

	WrapInfo *SecretWrapInfo `json:"wrap_info,omitempty"`
}

// ReadBytesWithContext is like ReadWithContext, but returns string values in
// Data as []byte.
func (c *Logical) ReadBytesWithContext(ctx context.Context, path string) (*RawSecret, error) {
	return c.ReadBytesWithDataWithContext(ctx, path, nil)
}

// ReadBytesWithDataWithContext is like ReadBytesWithContext, but the 'data'
// map is added as query parameters to the request.
func (c *Logical) ReadBytesWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*RawSecret, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	resp, err := c.readRawWithDataWithContext(ctx, path, data)
	return parseRawResponseAndCloseBody(resp, err)
}

// parseRawResponseAndCloseBody is ParseRawResponseAndCloseBody for RawSecret.
func parseRawResponseAndCloseBody(resp *Response, err error) (*RawSecret, error) {
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := ParseRawSecret(resp.Body)
		switch {
		case parseErr == nil:
		case errors.Is(parseErr, io.EOF):
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return ParseRawSecret(resp.Body)
}

// ParseRawSecret is ParseSecret, but string values in Data are returned as
// []byte.
func ParseRawSecret(r io.Reader) (*RawSecret, error) {
	// First read the data into a buffer. Not super efficient but we want to
	// know if we actually have a body or not.
	var buf bytes.Buffer

	// io.Reader is treated like a stream and cannot be read
	// multiple times. Duplicating this stream using TeeReader
	// to use this data in case there is no top-level data from
	// api response
	var teebuf bytes.Buffer
	tee := io.TeeReader(r, &teebuf)

	_, err := buf.ReadFrom(tee)
	if err != nil {
		return nil, err
	}
	if buf.Len() == 0 {
		return nil, nil
	}

	var wire rawSecretWire
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	if err := dec.Decode(&wire); err != nil {
		return nil, err
	}

	secret := &RawSecret{
		RequestID:     wire.RequestID,
		LeaseID:       wire.LeaseID,
		LeaseDuration: wire.LeaseDuration,
		Renewable:     wire.Renewable,
		Warnings:      wire.Warnings,
		Auth:          wire.Auth,
		WrapInfo:      wire.WrapInfo,
	}

	if wire.Data != nil {
		secret.Data, err = convertObject(wire.Data)
		if err != nil {
			return nil, err
		}
	}

	// If the secret is null, add raw data to secret data if present
	if reflect.DeepEqual(wire, rawSecretWire{}) {
		data := make(map[string]json.RawMessage)
		dec := json.NewDecoder(&teebuf)
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil, err
		}
		errRaw, errPresent := data["errors"]

		// if only errors are present in the resp.Body return nil
		// to return value not found as it does not have any raw data
		if len(data) == 1 && errPresent {
			return nil, nil
		}

		// if errors are present along with raw data return the error
		if errPresent {
			var errStrArray []string
			if err := json.Unmarshal(errRaw, &errStrArray); err != nil {
				return nil, err
			}
			return nil, errors.New(strings.Join(errStrArray, " "))
		}

		// if any raw data is present in resp.Body, add it to secret
		if len(data) > 0 {
			secret.Data, err = convertObject(data)
			if err != nil {
				return nil, err
			}
		}
	}

	return secret, nil
}

// convertObject converts every member of a raw JSON object.
func convertObject(obj map[string]json.RawMessage) (map[string]any, error) {
	out := make(map[string]any, len(obj))
	for key, raw := range obj {
		value, err := convertValue(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding field %q: %w", key, err)
		}
		out[key] = value
	}
	return out, nil
}

// convertValue converts a raw JSON value, decoding strings as []byte and
// recursing into objects and arrays. Numbers are kept as json.Number, as
// ParseSecret does. Nesting is bounded by the decoder, which rejects deeply
// nested documents before we get here.
func convertValue(raw json.RawMessage) (any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty JSON value")
	}

	switch trimmed[0] {
	case '"':
		return unquoteJSONString(trimmed)

	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, err
		}
		return convertObject(obj)

	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		out := make([]any, len(arr))
		for i, item := range arr {
			value, err := convertValue(item)
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil

	case 't':
		return true, nil

	case 'f':
		return false, nil

	case 'n':
		return nil, nil

	default:
		return json.Number(trimmed), nil
	}
}

// unquoteJSONString converts a quoted JSON string to []byte.
func unquoteJSONString(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("malformed JSON string")
	}

	raw = raw[1 : len(raw)-1]
	if bytes.IndexByte(raw, '\\') >= 0 {
		return nil, errors.New("escape sequences in strings are not supported")
	}

	return append(make([]byte, 0, len(raw)), raw...), nil
}
