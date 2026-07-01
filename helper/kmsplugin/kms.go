// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/openbao/go-kms-wrapping/kms/transit/v2"
	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

var builtinKMSes = map[string]func() kms.KMS{
	"transit": transit.New,
}

// OpenKMS creates a new KMS instance and calls Open with the provided options.
// This may dispatch to either a builtin KMS or an external pluginized one.
func (c *Catalog) OpenKMS(ctx context.Context, name string, opts *kms.OpenOptions) (s kms.KMS, err error) {
	client, ok, err := c.getClient(name)
	switch {
	case err != nil:
		return nil, err

	case !ok:
		// Try builtin KMSes.
		if builtin, ok := builtinKMSes[name]; ok {
			s = builtin()
		} else {
			return nil, fmt.Errorf("unknown KMS: %s", name)
		}

	default:
		defer func() {
			if err != nil {
				client.close()
			}
		}()

		// Each call to Dispense creates a new KMS instance on the remote.
		raw, err := client.Dispense("kms")
		if err != nil {
			return nil, err
		}

		s = &remoteKMS{
			client: client,
			kms:    raw.(kms.KMS),
		}
	}

	if err := s.Open(ctx, opts); err != nil {
		return nil, err
	}

	return s, nil
}

// remoteKMS adds plugin reloading & finalization hooks on top of a pluginized
// kms.KMS.
type remoteKMS struct {
	kms.UnimplementedKMS

	mu sync.RWMutex

	client *client
	kms    kms.KMS

	canary int
	opts   *kms.OpenOptions
}

// retry calls f and retries it once if interrupted by a plugin shutdown.
func (s *remoteKMS) retry(ctx context.Context, f func() error) error {
	var canary int

	// call is a helper to call f under a read lock and record the current
	// client pointer as a reload canary value.
	call := func() error {
		s.mu.RLock()
		defer s.mu.RUnlock()

		if s.kms == nil {
			return errors.New("KMS was closed")
		}

		canary = s.canary

		return f()
	}

	if err := call(); err != gkwplugin.ErrPluginShutdown {
		// Plugin works and call either succeeded or returned an
		// application-level error.
		return err
	}

	// Try to reload the plugin & reinstantiate the KMS.
	if err := s.reload(ctx, canary); err != nil {
		return err
	}

	// Then give this another shot.
	return call()
}

// reload attempts to reload the underlying plugin and reinstantiate the remote
// KMS instance.
func (s *remoteKMS) reload(ctx context.Context, canary int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil {
		return errors.New("KMS was closed")
	}

	if s.canary > canary {
		// Another caller managed to reload before we got the lock.
		return nil
	}

	client, err := s.client.catalog.reloadClient(s.client)
	if err != nil {
		return err
	}

	raw, err := client.Dispense("kms")
	if err != nil {
		return err
	}

	kms := raw.(kms.KMS)

	if s.opts != nil {
		// Replay Open if it was called on the original KMS.
		if err := kms.Open(ctx, s.opts); err != nil {
			return err
		}
	}

	// Update self on success.
	s.canary++
	s.client, s.kms = client, kms

	return nil
}

func (s *remoteKMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	if err := s.retry(ctx, func() error {
		return s.kms.Open(ctx, opts)
	}); err != nil {
		return err
	}

	// Save opts so Open can be replayed when the plugin is reloaded. We assume
	// that locking is not needed as Open calls should not be made concurrently.
	s.opts = opts

	return nil
}

func (s *remoteKMS) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	defer func() {
		s.kms = nil      // Mark as closed.
		s.client.close() // Release the client reference.
	}()

	// No need to retry, but ignore any plugin shutdown errors.
	switch err := s.kms.Close(ctx); err {
	case gkwplugin.ErrPluginShutdown:
		return nil
	default:
		return err
	}
}

func (s *remoteKMS) GetKey(ctx context.Context, opts *kms.KeyOptions) (key kms.Key, err error) {
	var canary int
	err = s.retry(ctx, func() error {
		canary = s.canary
		key, err = s.kms.GetKey(ctx, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &remoteKey{
		kms:    s,
		key:    key,
		canary: canary,
		opts:   opts,
	}, nil
}

// remoteKey adds plugin reloading & finalization hooks on top of a pluginized
// kms.Key.
type remoteKey struct {
	kms.UnimplementedKey

	mu sync.RWMutex

	kms *remoteKMS
	key kms.Key

	canary int
	opts   *kms.KeyOptions
}

// retry calls f and retries it once if interrupted by a plugin shutdown.
func (k *remoteKey) retry(ctx context.Context, f func() error) error {
	var canary int

	// call is a helper to call f under a read lock and record the current inner
	// key value as a reload canary values.
	call := func() error {
		k.mu.RLock()
		defer k.mu.RUnlock()

		k.kms.mu.RLock()
		defer k.kms.mu.RUnlock()

		switch {
		case k.key == nil:
			return errors.New("key was closed")
		case k.kms.kms == nil:
			return errors.New("KMS was closed")
		}

		canary = k.kms.canary

		return f()
	}

	if err := call(); !errors.Is(err, gkwplugin.ErrPluginShutdown) {
		// Plugin works and call either succeeded or returned an
		// application-level error.
		return err
	}

	// If we saw a shutdown error, give a first attempt to reloading only the
	// key, assuming the KMS may already have been reloaded by another call and
	// we just have a stale key.
	err := k.reload(ctx, canary)
	switch {
	case err == nil:
		return call()
	case !errors.Is(err, gkwplugin.ErrPluginShutdown):
		return err
	}

	// If we still see a shutdown error, reload the KMS, too.
	if err := k.kms.reload(ctx, canary); err != nil {
		return err
	}
	if err := k.reload(ctx, canary); err != nil {
		return err
	}

	// Then retry.
	return call()
}

// reload attempts to reinstantiate the remote key instance.
func (k *remoteKey) reload(ctx context.Context, canary int) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.kms.mu.RLock()
	defer k.kms.mu.RUnlock()

	switch {
	case k.key == nil:
		return errors.New("key was closed")
	case k.kms.kms == nil:
		return errors.New("KMS was closed")
	}

	if k.canary > canary {
		// Another caller managed to reload before we got the lock.
		return nil
	}

	// Note: This should call into the remoteKMS's underlying KMS instance, not
	// into its retry-wrapped method.
	key, err := k.kms.kms.GetKey(ctx, k.opts)
	if err != nil {
		return err
	}

	// Update self on success.
	k.key, k.canary = key, canary

	return nil
}

func (k *remoteKey) Encrypt(ctx context.Context, opts *kms.CipherOptions) (ciphertext []byte, err error) {
	err = k.retry(ctx, func() error {
		ciphertext, err = k.key.Encrypt(ctx, opts)
		return err
	})
	return ciphertext, err
}

func (k *remoteKey) Decrypt(ctx context.Context, opts *kms.CipherOptions) (plaintext []byte, err error) {
	err = k.retry(ctx, func() error {
		plaintext, err = k.key.Decrypt(ctx, opts)
		return err
	})
	return plaintext, err
}

func (k *remoteKey) Sign(ctx context.Context, opts *kms.SignOptions) (signature []byte, err error) {
	err = k.retry(ctx, func() error {
		signature, err = k.key.Sign(ctx, opts)
		return err
	})
	return signature, err
}

func (k *remoteKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	return k.retry(ctx, func() error {
		return k.key.Verify(ctx, opts)
	})
}

func (k *remoteKey) ExportPublic(ctx context.Context) (public crypto.PublicKey, err error) {
	err = k.retry(ctx, func() error {
		public, err = k.key.ExportPublic(ctx)
		return err
	})
	return public, err
}

func (k *remoteKey) Close(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	defer func() {
		k.key = nil // Mark as closed.
	}()

	// No need to retry, but ignore any plugin shutdown errors.
	switch err := k.key.Close(ctx); err {
	case gkwplugin.ErrPluginShutdown:
		return nil
	default:
		return err
	}
}
