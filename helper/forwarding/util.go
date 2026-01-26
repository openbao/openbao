// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package forwarding

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	"github.com/openbao/openbao/helper/buffer"
)

type bufCloser struct {
	*bytes.Buffer
}

func (b bufCloser) Close() error {
	b.Reset()
	return nil
}

func GenerateForwardedRequest(req *http.Request) (*Request, error) {
	var reader io.Reader = req.Body
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	fq := Request{
		Method:        req.Method,
		HeaderEntries: make(map[string]*HeaderEntry, len(req.Header)),
		Host:          req.Host,
		RemoteAddr:    req.RemoteAddr,
		Body:          body,
	}

	reqURL := req.URL
	fq.Url = &URL{
		Scheme:   reqURL.Scheme,
		Opaque:   reqURL.Opaque,
		Host:     reqURL.Host,
		Path:     reqURL.Path,
		RawPath:  reqURL.RawPath,
		RawQuery: reqURL.RawQuery,
		Fragment: reqURL.Fragment,
	}

	for k, v := range req.Header {
		fq.HeaderEntries[k] = &HeaderEntry{
			Values: v,
		}
	}

	if req.TLS != nil && req.TLS.PeerCertificates != nil && len(req.TLS.PeerCertificates) > 0 {
		fq.PeerCertificates = make([][]byte, len(req.TLS.PeerCertificates))
		for i, cert := range req.TLS.PeerCertificates {
			fq.PeerCertificates[i] = cert.Raw
		}
	}

	return &fq, nil
}

func ParseForwardedRequest(fq *Request) (*http.Request, error) {
	body, err := buffer.NewSeekableReader(bytes.NewReader(fq.Body))
	if err != nil {
		return nil, err
	}

	ret := &http.Request{
		Method:     fq.Method,
		Header:     make(map[string][]string, len(fq.HeaderEntries)),
		Body:       body,
		Host:       fq.Host,
		RemoteAddr: fq.RemoteAddr,
	}

	ret.URL = &url.URL{
		Scheme:   fq.Url.Scheme,
		Opaque:   fq.Url.Opaque,
		Host:     fq.Url.Host,
		Path:     fq.Url.Path,
		RawPath:  fq.Url.RawPath,
		RawQuery: fq.Url.RawQuery,
		Fragment: fq.Url.Fragment,
	}

	for k, v := range fq.HeaderEntries {
		ret.Header[k] = v.Values
	}

	if len(fq.PeerCertificates) > 0 {
		ret.TLS = &tls.ConnectionState{
			PeerCertificates: make([]*x509.Certificate, len(fq.PeerCertificates)),
		}
		for i, certBytes := range fq.PeerCertificates {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, err
			}
			ret.TLS.PeerCertificates[i] = cert
		}
	}

	return ret, nil
}

type RPCResponseWriter struct {
	statusCode int
	header     http.Header
	body       *bytes.Buffer
}

// NewRPCResponseWriter returns an initialized RPCResponseWriter
func NewRPCResponseWriter() *RPCResponseWriter {
	w := &RPCResponseWriter{
		header:     make(http.Header),
		body:       new(bytes.Buffer),
		statusCode: 200,
	}
	// w.header.Set("Content-Type", "application/octet-stream")
	return w
}

func (w *RPCResponseWriter) Header() http.Header {
	return w.header
}

func (w *RPCResponseWriter) Write(buf []byte) (int, error) {
	w.body.Write(buf)
	return len(buf), nil
}

func (w *RPCResponseWriter) WriteHeader(code int) {
	w.statusCode = code
}

func (w *RPCResponseWriter) StatusCode() int {
	return w.statusCode
}

func (w *RPCResponseWriter) Body() *bytes.Buffer {
	return w.body
}
