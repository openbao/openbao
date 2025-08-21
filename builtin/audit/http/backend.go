// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/audit"
	"github.com/openbao/openbao/sdk/v2/helper/salt"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/version"
)

// Backend is the audit backend for the http-based audit store.
//
// This presently has little logic to handle retrying failed requests.
type Backend struct {
	uri     string
	headers http.Header

	formatter    audit.AuditFormatter
	formatConfig audit.FormatterConfig

	clientLock sync.RWMutex
	client     *http.Client

	saltMutex  sync.RWMutex
	salt       *atomic.Value
	saltConfig *salt.Config
	saltView   logical.Storage
}

var _ audit.Backend = (*Backend)(nil)

func Factory(ctx context.Context, conf *audit.BackendConfig) (audit.Backend, error) {
	if conf.SaltConfig == nil {
		return nil, errors.New("nil salt config")
	}
	if conf.SaltView == nil {
		return nil, errors.New("nil salt view")
	}

	uriRaw, ok := conf.Config["uri"]
	if !ok {
		return nil, errors.New("uri is required")
	}

	// resolve URI to a concrete value
	uri, err := parseutil.ParsePath(uriRaw, parseutil.WithNoTrimSpaces(true), parseutil.WithErrorOnMissingEnv(true))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve uri: %w", err)
	}

	if _, err := url.Parse(uri); err != nil {
		return nil, fmt.Errorf("failed to parse uri: %w", err)
	}

	// config is string->string, so we need to handle JSON decoding headers.
	headers := http.Header{}
	headersRaw, ok := conf.Config["headers"]
	if ok {
		var decodedHeaders map[string][]string
		if err := json.Unmarshal([]byte(headersRaw), &decodedHeaders); err != nil {
			return nil, fmt.Errorf("failed to parse headers: %w", err)
		}

		// Also perform URI based replacement on header values to allow
		// environment variables and files to provide token authentication for
		// external servers. With API-based audits this is unsafe but the new
		// declarative config-driven audit device creation this is fully
		// controlled by the operator.
		for header, values := range decodedHeaders {
			for _, value := range values {
				modified, err := parseutil.ParsePath(value, parseutil.WithNoTrimSpaces(true), parseutil.WithErrorOnMissingEnv(true))
				if err != nil {
					return nil, fmt.Errorf("failed to parse header %v: %w", header, nil)
				}

				headers.Add(header, modified)
			}
		}
	}

	// Handle output format.
	format, ok := conf.Config["format"]
	if !ok {
		format = "json"
	}
	switch format {
	case "json", "jsonx":
	default:
		return nil, fmt.Errorf("unknown format type %q", format)
	}

	// Check if hashing of accessor is disabled
	hmacAccessor := true
	if hmacAccessorRaw, ok := conf.Config["hmac_accessor"]; ok {
		value, err := strconv.ParseBool(hmacAccessorRaw)
		if err != nil {
			return nil, err
		}
		hmacAccessor = value
	}

	// Check if raw logging is enabled
	logRaw := false
	if raw, ok := conf.Config["log_raw"]; ok {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, err
		}
		logRaw = b
	}

	elideListResponses := false
	if elideListResponsesRaw, ok := conf.Config["elide_list_responses"]; ok {
		value, err := strconv.ParseBool(elideListResponsesRaw)
		if err != nil {
			return nil, err
		}
		elideListResponses = value
	}

	b := &Backend{
		uri:     uri,
		headers: headers,

		formatConfig: audit.FormatterConfig{
			Raw:                logRaw,
			HMACAccessor:       hmacAccessor,
			ElideListResponses: elideListResponses,
		},

		saltConfig: conf.SaltConfig,
		saltView:   conf.SaltView,
		salt:       new(atomic.Value),
	}

	// Ensure we are working with the right type by explicitly storing a nil of
	// the right type
	b.salt.Store((*salt.Salt)(nil))

	switch format {
	case "json":
		b.formatter.AuditFormatWriter = &audit.JSONFormatWriter{
			Prefix:   conf.Config["prefix"],
			SaltFunc: b.Salt,
		}
	case "jsonx":
		b.formatter.AuditFormatWriter = &audit.JSONxFormatWriter{
			Prefix:   conf.Config["prefix"],
			SaltFunc: b.Salt,
		}
	}

	if _, err := b.getClient(); err != nil {
		return nil, fmt.Errorf("unable to create http client: %w", err)
	}

	return b, nil
}

func (b *Backend) Salt(ctx context.Context) (*salt.Salt, error) {
	s := b.salt.Load().(*salt.Salt)
	if s != nil {
		return s, nil
	}

	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()

	s = b.salt.Load().(*salt.Salt)
	if s != nil {
		return s, nil
	}

	newSalt, err := salt.NewSalt(ctx, b.saltView, b.saltConfig)
	if err != nil {
		b.salt.Store((*salt.Salt)(nil))
		return nil, err
	}

	b.salt.Store(newSalt)
	return newSalt, nil
}

func (b *Backend) GetHash(ctx context.Context, data string) (string, error) {
	salt, err := b.Salt(ctx)
	if err != nil {
		return "", err
	}

	return audit.HashString(salt, data), nil
}

func (b *Backend) LogRequest(ctx context.Context, in *logical.LogInput) error {
	buf := bytes.NewBuffer(make([]byte, 0, 2000))
	err := b.formatter.FormatRequest(ctx, buf, b.formatConfig, in)
	if err != nil {
		return err
	}

	return b.log(ctx, buf)
}

func (b *Backend) log(ctx context.Context, buf *bytes.Buffer) error {
	reader := bytes.NewReader(buf.Bytes())

	client, err := b.getClient()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.uri, reader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header = b.headers.Clone()

	if value := b.headers.Get("User-Agent"); value != "" {
		req.Header.Add("User-Agent", fmt.Sprintf("OpenBaoAuditor/%s", version.GetVersion().VersionNumber()))
	}

	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return fmt.Errorf("failed to perform request: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("failed to close body: %w", err)
	}

	// Redirects and errors will not be accepted.
	if resp.StatusCode >= 300 {
		return fmt.Errorf("failed to perform request: status code not 2xx: %v", resp.StatusCode)
	}

	return nil
}

func (b *Backend) LogResponse(ctx context.Context, in *logical.LogInput) error {
	buf := bytes.NewBuffer(make([]byte, 0, 6000))
	err := b.formatter.FormatResponse(ctx, buf, b.formatConfig, in)
	if err != nil {
		return err
	}

	return b.log(ctx, buf)
}

func (b *Backend) LogTestMessage(ctx context.Context, in *logical.LogInput, config map[string]string) error {
	var buf bytes.Buffer
	temporaryFormatter := audit.NewTemporaryFormatter(config["format"], config["prefix"])
	if err := temporaryFormatter.FormatRequest(ctx, &buf, b.formatConfig, in); err != nil {
		return err
	}

	return b.log(ctx, &buf)
}

func (b *Backend) getClient() (*http.Client, error) {
	b.clientLock.RLock()
	client := b.client
	b.clientLock.RUnlock()

	if client != nil {
		return client, nil
	}

	b.clientLock.Lock()
	defer b.clientLock.Unlock()

	if b.client != nil {
		return client, nil
	}

	// TODO (ascheel): use a different HTTP client.
	b.client = http.DefaultClient

	return b.client, nil
}

func (b *Backend) Reload(_ context.Context) error {
	b.clientLock.Lock()
	defer b.clientLock.Unlock()

	b.client = nil

	_, err := b.getClient()
	if err != nil {
		return err
	}

	return nil
}

func (b *Backend) Invalidate(_ context.Context) {
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()

	b.salt.Store((*salt.Salt)(nil))
}
