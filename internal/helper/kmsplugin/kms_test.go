// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"crypto/ed25519"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/stretchr/testify/require"
)

func TestKMS(t *testing.T) {
	ctx := t.Context()

	// Start out by setting up a Transit engine server to test against.
	clusterOpts := docker.DefaultOptions(t)
	clusterOpts.Storage = docker.InmemStorage{}
	clusterOpts.NumCores = 1
	clusterOpts.HADisabled = true

	cluster := docker.NewTestDockerCluster(t, clusterOpts)
	defer cluster.Cleanup()

	client := cluster.ClusterNodes[0].APIClient()

	require.NoError(t, client.Sys().Mount("transit", &api.MountInput{
		Type: "transit",
	}))

	// Create some keys to play with.
	for _, name := range []string{
		"aes256-gcm96", "ed25519",
	} {
		_, err := client.Logical().WriteWithContext(ctx, path.Join("transit/keys", name), map[string]any{
			"type": name,
		})
		require.NoError(t, err)
	}

	opts := &kms.OpenOptions{
		ConfigMap: kms.ConfigMap{
			"address":         client.Address(),
			"token":           client.Token(),
			"tls_ca_cert":     string(cluster.CACertPEM),
			"disable_renewal": true,
		},
	}

	t.Run("builtin", func(t *testing.T) {
		catalog, err := NewCatalog(hclog.Default(), &server.Config{})
		require.NoError(t, err)

		_, err = catalog.OpenKMS(ctx, "bogus", opts)
		require.Error(t, err)

		s, err := catalog.OpenKMS(ctx, "transit", opts)
		require.NoError(t, err)
		require.IsNotType(t, &remoteKMS{}, s)
		require.NoError(t, s.Close(ctx))
	})

	config := &server.Config{
		PluginDirectory: filepath.Dir(os.Args[0]),
		Plugins:         []*server.PluginConfig{TransitPluginConfig},
	}

	catalog, err := NewCatalog(hclog.Default(), config)
	require.NoError(t, err)

	_, err = catalog.OpenKMS(ctx, "bogus", opts)
	require.Error(t, err)

	s, err := catalog.OpenKMS(ctx, "transit", opts)
	require.NoError(t, err)
	require.IsType(t, &remoteKMS{}, s)

	defer func() {
		require.NoError(t, s.Close(ctx))
	}()

	input := []byte("tom")

	t.Run("Encrypt+Decrypt", func(t *testing.T) {
		key, err := s.GetKey(ctx, &kms.KeyOptions{
			ConfigMap: kms.ConfigMap{"name": "aes256-gcm96"},
		})
		require.NoError(t, err)

		defer func() {
			require.NoError(t, key.Close(ctx))
		}()

		opts := &kms.CipherOptions{Data: input}
		ciphertext, err := key.Encrypt(ctx, opts)
		require.NoError(t, err)

		plaintext, err := key.Decrypt(ctx, &kms.CipherOptions{
			Data:       ciphertext,
			Nonce:      opts.Nonce,
			KeyVersion: opts.KeyVersion,
		})
		require.NoError(t, err)
		require.Equal(t, input, plaintext)
	})

	t.Run("Sign+Verify", func(t *testing.T) {
		key, err := s.GetKey(ctx, &kms.KeyOptions{
			ConfigMap: kms.ConfigMap{"name": "ed25519"},
		})
		require.NoError(t, err)

		defer func() {
			require.NoError(t, key.Close(ctx))
		}()

		opts := &kms.SignOptions{Data: input}
		sig, err := key.Sign(ctx, opts)
		require.NoError(t, err)

		require.NoError(t, key.Verify(ctx, &kms.VerifyOptions{
			Data:       input,
			Signature:  sig,
			KeyVersion: opts.KeyVersion,
		}))
	})

	t.Run("ExportPublic", func(t *testing.T) {
		key, err := s.GetKey(ctx, &kms.KeyOptions{
			ConfigMap: kms.ConfigMap{"name": "ed25519"},
		})
		require.NoError(t, err)

		defer func() {
			require.NoError(t, key.Close(ctx))
		}()

		pub, err := key.ExportPublic(ctx)
		require.NoError(t, err)
		require.IsType(t, ed25519.PublicKey{}, pub)
	})

	t.Run("reload", func(t *testing.T) {
		catalog, err := NewCatalog(hclog.Default(), config)
		require.NoError(t, err)

		// Open two instances of KMS from the same plugin.
		s1, err := catalog.OpenKMS(ctx, "transit", opts)
		require.NoError(t, err)
		s2, err := catalog.OpenKMS(ctx, "transit", opts)
		require.NoError(t, err)

		// Acquire a key from each instance.
		k1, err := s1.GetKey(ctx, &kms.KeyOptions{
			ConfigMap: kms.ConfigMap{"name": "ed25519"},
		})
		require.NoError(t, err)
		k2, err := s2.GetKey(ctx, &kms.KeyOptions{
			ConfigMap: kms.ConfigMap{"name": "ed25519"},
		})
		require.NoError(t, err)

		// Simulate a crashed plugin.
		s1.(*remoteKMS).client.process.Kill()

		// Check that both keys recover.
		_, err = k1.Sign(ctx, &kms.SignOptions{Data: []byte("foo")})
		require.NoError(t, err)
		_, err = k2.Sign(ctx, &kms.SignOptions{Data: []byte("foo")})
		require.NoError(t, err)

		// Kill again, but this time dispatch a KMS-level request before
		// touching the key so the key must be re-fetched but the plugin was
		// already reloaded.
		s1.(*remoteKMS).client.process.Kill()

		// KMS-level request, this should reload the KMS but no keys.
		k3, err := s1.GetKey(ctx, &kms.KeyOptions{
			ConfigMap: kms.ConfigMap{"name": "ed25519"},
		})
		require.NoError(t, err)

		// Pull these out to demonstrate that the key will reload without
		// reloading the KMS if the KMS has already been reloaded.
		inner := k1.(*remoteKey)
		innerKey, innerKMS := inner.key, inner.kms.kms

		// Now try to use k1, which should reload the key automatically.
		_, err = k1.Sign(ctx, &kms.SignOptions{Data: []byte("foo")})
		require.NoError(t, err)

		// Assert that we haven't recycled the KMS, but the key was renewed.
		require.True(t, innerKey != inner.key)
		require.True(t, innerKMS == inner.kms.kms)

		// Close everything.
		require.NoError(t, k1.Close(ctx))
		require.NoError(t, k2.Close(ctx))
		require.NoError(t, k3.Close(ctx))
		require.NoError(t, s1.Close(ctx))
		require.NoError(t, s2.Close(ctx))
	})
}
