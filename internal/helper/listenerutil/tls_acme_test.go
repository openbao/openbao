// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/v2/internal/helper/configutil"
)

func TestACMECertGetter(t *testing.T) {
	const caDirectory = "http://127.0.0.1:9999/v1/pki/acme/directory"

	newTestACMECertGetter := func(t *testing.T, l *configutil.Listener) *ACMECertGetter {
		t.Helper()

		cg, err := NewCertificateGetter(l, nil, hclog.NewNullLogger())
		require.NoError(t, err)

		acg, ok := cg.(*ACMECertGetter)
		require.True(t, ok, "expected *ACMECertGetter, got %T", cg)
		t.Cleanup(func() {
			acg.Close() //nolint:errcheck
		})
		return acg
	}

	t.Run("listener config correctly setup", func(t *testing.T) {
		dir := t.TempDir()

		acg := newTestACMECertGetter(t, &configutil.Listener{
			TLSACMECADirectory: caDirectory,
			TLSACMECachePath:   dir,
			TLSACMEKeyType:     string(certmagic.RSA4096),
		})

		require.Equal(t, dir, acg.Magic.Storage.(*certmagic.FileStorage).Path)
		require.NotNil(t, acg.Magic.OnDemand)
		require.Equal(t, caDirectory, acg.ACME.CA)
		require.Equal(t, certmagic.StandardKeyGenerator{KeyType: certmagic.RSA4096}, acg.Magic.KeySource)
	})
}
