// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/jefferai/jsonx"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
)

// JSONxFormatWriter is an AuditFormatWriter implementation that structures data into
// a XML format.
type JSONxFormatWriter struct {
	Prefix   string
	SaltFunc func(context.Context) (*salt.Salt, error)
}

func (f *JSONxFormatWriter) WriteRequest(w io.Writer, req *AuditRequestEntry) error {
	if req == nil {
		return errors.New("request entry was nil, cannot encode")
	}

	if len(f.Prefix) > 0 {
		_, err := w.Write([]byte(f.Prefix))
		if err != nil {
			return err
		}
	}

	jsonBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	xmlBytes, err := jsonx.EncodeJSONBytes(jsonBytes)
	if err != nil {
		return err
	}

	_, err = w.Write(xmlBytes)
	return err
}

func (f *JSONxFormatWriter) WriteResponse(w io.Writer, resp *AuditResponseEntry) error {
	if resp == nil {
		return errors.New("response entry was nil, cannot encode")
	}

	if len(f.Prefix) > 0 {
		_, err := w.Write([]byte(f.Prefix))
		if err != nil {
			return err
		}
	}

	jsonBytes, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	xmlBytes, err := jsonx.EncodeJSONBytes(jsonBytes)
	if err != nil {
		return err
	}

	_, err = w.Write(xmlBytes)
	return err
}

func (f *JSONxFormatWriter) Salt(ctx context.Context) (*salt.Salt, error) {
	return f.SaltFunc(ctx)
}
