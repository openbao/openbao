// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/mholt/acmez/v3/acme"
	"github.com/mitchellh/cli"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/version"
)

type ReloadableCertGetter interface {
	Reload() error
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type ACMECertGetter struct {
	Listener *configutil.Listener

	Magic *certmagic.Config
	ACME  *certmagic.ACMEIssuer
}

func NewCertificateGetter(l *configutil.Listener, ui cli.Ui, logger hclog.Logger) (ReloadableCertGetter, error) {
	// Assume a validated listener here. Prefer the certificate if is set
	// by path in the listener configuration, otherwise do ACME certificate
	// acquisition.
	if l.TLSCertFile != "" {
		cg := reloadutil.NewCertificateGetter(l.TLSCertFile, l.TLSKeyFile, "")
		if err := cg.Reload(); err != nil {
			// We try the key without a passphrase first and if we get an incorrect
			// passphrase response, try again after prompting for a passphrase
			if errwrap.Contains(err, x509.IncorrectPasswordError.Error()) {
				var passphrase string
				passphrase, err = ui.AskSecret(fmt.Sprintf("Enter passphrase for %s:", l.TLSKeyFile))
				if err == nil {
					cg = reloadutil.NewCertificateGetter(l.TLSCertFile, l.TLSKeyFile, passphrase)
					if err = cg.Reload(); err == nil {
						return cg, nil
					}

					return nil, fmt.Errorf("error loading TLS cert with password: %w", err)
				}
			}

			return nil, fmt.Errorf("error loading TLS cert: %w", err)
		}

		return cg, nil
	}

	core := &zapHclCore{Logger: logger}
	zapLogger := zap.New(core)
	if logger == nil {
		zapLogger = zap.NewNop()
	}
	certmagic.Default.Logger = zapLogger

	acg := &ACMECertGetter{
		Listener: l,
		Magic:    certmagic.NewDefault(),
	}

	acg.Magic.OnDemand = new(certmagic.OnDemandConfig)
	acg.Magic.OnDemand.DecisionFunc = func(ctx context.Context, name string) error {
		if len(l.TLSACMEDomains) == 0 {
			return nil
		}

		found := false
		for _, allowed := range l.TLSACMEDomains {
			if strings.EqualFold(allowed, name) {
				found = true
				break
			}
		}

		if !found {
			return errors.New("domain not allowed in tls_acme_domains")
		}

		return nil
	}

	if l.TLSACMECachePath != "" {
		acg.Magic.Storage = &certmagic.FileStorage{
			Path: l.TLSACMECachePath,
		}
	}

	if l.TLSACMEKeyType != "" {
		switch certmagic.KeyType(l.TLSACMEKeyType) {
		case certmagic.ED25519, certmagic.P256, certmagic.P384, certmagic.RSA2048, certmagic.RSA4096, certmagic.RSA8192:
		default:
			return nil, fmt.Errorf("unknown value for tls_acme_key_type (`%v`); allowed values are `%v`, `%v`, `%v`, `%v`, `%v`, `%v`", l.TLSACMEKeyType, certmagic.ED25519, certmagic.P256, certmagic.P384, certmagic.RSA2048, certmagic.RSA4096, certmagic.RSA8192)
		}

		acg.Magic.KeySource = certmagic.StandardKeyGenerator{
			KeyType: certmagic.KeyType(l.TLSACMEKeyType),
		}
	}

	template := certmagic.ACMEIssuer{
		CA:                      l.TLSACMECADirectory,
		TestCA:                  l.TLSACMETestCADirectory,
		Email:                   l.TLSACMEEmail,
		Agreed:                  true,
		Logger:                  zapLogger,
		DisableHTTPChallenge:    l.TLSACMEDisableHttpChallenge,
		DisableTLSALPNChallenge: l.TLSACMEDisableAlpnChallenge,
	}

	if l.TLSACMECARoot != "" {
		caPool := x509.NewCertPool()

		data, err := ioutil.ReadFile(l.TLSACMECARoot)
		if err != nil {
			return nil, fmt.Errorf("failed to read ACME CA file: %w", err)
		}

		if !caPool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to parse ACME CA certificate")
		}

		template.TrustedRoots = caPool
	}

	if l.TLSACMEEABKeyId != "" {
		template.ExternalAccount = &acme.EAB{
			KeyID:  l.TLSACMEEABKeyId,
			MACKey: l.TLSACMEEABMacKey,
		}
	}

	acg.ACME = certmagic.NewACMEIssuer(acg.Magic, template)
	acg.Magic.Issuers = []certmagic.Issuer{acg.ACME}

	return acg, nil
}

func (c *ACMECertGetter) ALPNProtos() []string {
	return []string{"acme-tls/1"}
}

func (c *ACMECertGetter) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) bool {
	return c.ACME.HandleHTTPChallenge(w, r)
}

func (c *ACMECertGetter) Reload() error { return nil }

func (c *ACMECertGetter) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// ACMECertGetter follows the strategy by Caddy of on-demand TLS
	// configuration: when a connection comes in for a domain, attempt to
	// get a valid certificate from the ACME responder, just-in-time.
	return c.Magic.GetCertificate(hello)
}

type zapHclCore struct {
	Logger hclog.Logger
}

var _ zapcore.Core = &zapHclCore{}

func (z *zapHclCore) Enabled(zapcore.Level) bool        { return true }
func (z *zapHclCore) With([]zapcore.Field) zapcore.Core { return z }
func (z *zapHclCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return checked.AddCore(entry, z)
}

func (z *zapHclCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	var args []interface{}
	msg := entry.Message

	logger := z.Logger.Named("listener-acme")
	if len(entry.LoggerName) > 0 {
		logger = logger.Named(entry.LoggerName)
	}

	for _, field := range fields {
		if field.Type == zapcore.SkipType {
			continue
		}

		args = append(args, field.Key)

		// Conversion modified from https://github.com/uber-go/zap/blob/v1.27.0/zapcore/field.go#L114.
		switch field.Type {
		case zapcore.BoolType:
			args = append(args, field.Integer == 1)
		case zapcore.DurationType:
			args = append(args, time.Duration(field.Integer))
		case zapcore.Float64Type:
			args = append(args, math.Float64frombits(uint64(field.Integer)))
		case zapcore.Float32Type:
			args = append(args, math.Float32frombits(uint32(field.Integer)))
		case zapcore.Int64Type:
			args = append(args, field.Integer)
		case zapcore.Int32Type:
			args = append(args, int32(field.Integer))
		case zapcore.Int16Type:
			args = append(args, int16(field.Integer))
		case zapcore.Int8Type:
			args = append(args, int8(field.Integer))
		case zapcore.StringType:
			args = append(args, field.String)
		case zapcore.TimeType:
			if field.Interface != nil {
				args = append(args, time.Unix(0, field.Integer).In(field.Interface.(*time.Location)))
			} else {
				// Fall back to UTC if location is nil.
				args = append(args, time.Unix(0, field.Integer))
			}
		case zapcore.Uint64Type:
			args = append(args, uint64(field.Integer))
		case zapcore.Uint32Type:
			args = append(args, uint32(field.Integer))
		case zapcore.Uint16Type:
			args = append(args, uint16(field.Integer))
		case zapcore.Uint8Type:
			args = append(args, uint8(field.Integer))
		case zapcore.UintptrType:
			args = append(args, uintptr(field.Integer))
		default:
			args = append(args, field.Interface)
		}
	}

	switch entry.Level {
	case zapcore.DebugLevel:
		logger.Debug(msg, args...)
	case zapcore.InfoLevel:
		logger.Info(msg, args...)
	case zapcore.WarnLevel:
		logger.Warn(msg, args...)
	case zapcore.ErrorLevel:
		logger.Error(msg, args...)
	case zapcore.DPanicLevel:
		logger.Error(msg, args...)
		if strings.Contains(version.GetVersion().Version, "HEAD") {
			panic("development mode logger panic")
		}
	case zapcore.PanicLevel:
		logger.Error(msg, args...)
		panic("a fatal error occurred; exiting")
	case zapcore.FatalLevel:
		logger.Error(msg, args...)
		os.Exit(1)
	}
	return nil
}

func (z *zapHclCore) Sync() error { return nil }
