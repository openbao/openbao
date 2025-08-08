// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/helper/testhelpers"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault"
	"github.com/openbao/openbao/vault/seal"
	"github.com/stretchr/testify/require"
)

func TestSysRotate_Verification(t *testing.T) {
	testcases := []struct {
		recovery   bool
		deprecated bool
	}{
		{recovery: true, deprecated: true},
		{recovery: false, deprecated: true},
		{recovery: true, deprecated: false},
		{recovery: false, deprecated: false},
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("deprecated=%v with recovery=%v", tc.deprecated, tc.recovery), func(t *testing.T) {
			t.Parallel()
			if tc.deprecated {
				testSysRekey_VerificationDeprecated(t, tc.recovery)
			} else {
				testSysRotate_Verification(t, tc.recovery)
			}
		})
	}
}

func testSysRekey_VerificationDeprecated(t *testing.T, recovery bool) {
	opts := &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	}
	switch {
	case recovery:
		opts.SealFunc = func() vault.Seal {
			return vault.NewTestSeal(t, &seal.TestSealOpts{
				StoredKeys: seal.StoredKeysSupportedGeneric,
			})
		}
	}
	inm, err := inmem.NewInmemHA(nil, logging.NewVaultLogger(hclog.Debug))
	if err != nil {
		t.Fatal(err)
	}
	conf := vault.CoreConfig{
		Physical: inm,
	}
	cluster := vault.NewTestCluster(t, &conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client
	client.SetMaxRetries(0)

	initFunc := client.Sys().RekeyInit
	updateFunc := client.Sys().RekeyUpdate
	verificationUpdateFunc := client.Sys().RekeyVerificationUpdate
	verificationStatusFunc := client.Sys().RekeyVerificationStatus
	verificationCancelFunc := client.Sys().RekeyVerificationCancel
	if recovery {
		initFunc = client.Sys().RekeyRecoveryKeyInit
		updateFunc = client.Sys().RekeyRecoveryKeyUpdate
		verificationUpdateFunc = client.Sys().RekeyRecoveryKeyVerificationUpdate
		verificationStatusFunc = client.Sys().RekeyRecoveryKeyVerificationStatus
		verificationCancelFunc = client.Sys().RekeyRecoveryKeyVerificationCancel
	}

	var verificationNonce string
	var newKeys []string
	doRekeyInitialSteps := func() {
		status, err := initFunc(&api.RotateInitRequest{
			SecretShares:        5,
			SecretThreshold:     3,
			RequireVerification: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if status == nil {
			t.Fatal("nil status")
		}
		if !status.VerificationRequired {
			t.Fatal("expected verification required")
		}

		keys := cluster.BarrierKeys
		if recovery {
			keys = cluster.RecoveryKeys
		}
		var resp *api.RotateUpdateResponse
		for i := 0; i < 3; i++ {
			resp, err = updateFunc(base64.StdEncoding.EncodeToString(keys[i]), status.Nonce)
			if err != nil {
				t.Fatal(err)
			}
		}
		switch {
		case !resp.Complete:
			t.Fatal("expected completion")
		case !resp.VerificationRequired:
			t.Fatal("expected verification required")
		case resp.VerificationNonce == "":
			t.Fatal("verification nonce expected")
		}
		verificationNonce = resp.VerificationNonce
		newKeys = resp.KeysB64
		t.Logf("verification nonce: %q", verificationNonce)
	}

	doRekeyInitialSteps()

	// We are still going, so should not be able to init again
	_, err = initFunc(&api.RotateInitRequest{
		SecretShares:        5,
		SecretThreshold:     3,
		RequireVerification: true,
	})
	if err == nil {
		t.Fatal("expected error")
	}

	// Sealing should clear state, so after this we should be able to perform
	// the above again
	cluster.EnsureCoresSealed(t)
	if err := cluster.UnsealCoresWithError(recovery); err != nil {
		t.Fatal(err)
	}
	doRekeyInitialSteps()

	doStartVerify := func() {
		// Start the process
		for i := 0; i < 2; i++ {
			status, err := verificationUpdateFunc(newKeys[i], verificationNonce)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case status.Nonce != verificationNonce:
				t.Fatalf("unexpected nonce, expected %q, got %q", verificationNonce, status.Nonce)
			case status.Complete:
				t.Fatal("unexpected completion")
			}
		}

		// Check status
		vStatus, err := verificationStatusFunc()
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case vStatus.Nonce != verificationNonce:
			t.Fatalf("unexpected nonce, expected %q, got %q", verificationNonce, vStatus.Nonce)
		case vStatus.T != 3:
			t.Fatal("unexpected threshold")
		case vStatus.N != 5:
			t.Fatal("unexpected number of new keys")
		case vStatus.Progress != 2:
			t.Fatal("unexpected progress")
		}
	}

	doStartVerify()

	// Cancel; this should still keep the rekey process going but just cancel
	// the verification operation
	err = verificationCancelFunc()
	if err != nil {
		t.Fatal(err)
	}
	// Verify cannot init again
	_, err = initFunc(&api.RotateInitRequest{
		SecretShares:        5,
		SecretThreshold:     3,
		RequireVerification: true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	vStatus, err := verificationStatusFunc()
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case vStatus.Nonce == verificationNonce:
		t.Fatalf("unexpected nonce, expected not-%q but got it", verificationNonce)
	case vStatus.T != 3:
		t.Fatal("unexpected threshold")
	case vStatus.N != 5:
		t.Fatal("unexpected number of new keys")
	case vStatus.Progress != 0:
		t.Fatal("unexpected progress")
	}

	verificationNonce = vStatus.Nonce
	doStartVerify()

	if !recovery {
		// Sealing should clear state, but we never actually finished, so it should
		// still be the old keys (which are still currently set)
		cluster.EnsureCoresSealed(t)
		cluster.UnsealCores(t)
		vault.TestWaitActive(t, cluster.Cores[0].Core)

		// Should be able to init again and get back to where we were
		doRekeyInitialSteps()
		doStartVerify()
	} else {
		// We haven't finished, so generating a root token should still be the
		// old keys (which are still currently set)
		testhelpers.GenerateRoot(t, cluster, testhelpers.GenerateRootRegular)
	}

	// Provide the final new key
	vuStatus, err := verificationUpdateFunc(newKeys[2], verificationNonce)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case vuStatus.Nonce != verificationNonce:
		t.Fatalf("unexpected nonce, expected %q, got %q", verificationNonce, vuStatus.Nonce)
	case !vuStatus.Complete:
		t.Fatal("expected completion")
	}

	if !recovery {
		// Seal and unseal -- it should fail to unseal because the key has now been
		// rotated
		cluster.EnsureCoresSealed(t)

		// Simulate restarting Vault rather than just a seal/unseal, because
		// the standbys may not have had time to learn about the new key before
		// we sealed them.  We could sleep, but that's unreliable.
		oldKeys := cluster.BarrierKeys
		opts.SkipInit = true
		opts.SealFunc = nil // post rekey we should use the barrier config on disk
		cluster = vault.NewTestCluster(t, &conf, opts)
		cluster.BarrierKeys = oldKeys
		cluster.Start()
		defer cluster.Cleanup()

		if err := cluster.UnsealCoresWithError(false); err == nil {
			t.Fatal("expected error")
		}

		// Swap out the keys with our new ones and try again
		var newKeyBytes [][]byte
		for _, key := range newKeys {
			val, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				t.Fatal(err)
			}
			newKeyBytes = append(newKeyBytes, val)
		}
		cluster.BarrierKeys = newKeyBytes
		if err := cluster.UnsealCoresWithError(false); err != nil {
			t.Fatal(err)
		}
	} else {
		// The old keys should no longer work
		_, err := testhelpers.GenerateRootWithError(t, cluster, testhelpers.GenerateRootRegular)
		if err == nil {
			t.Fatal("expected error")
		}

		// Put the new keys in place and run again
		cluster.RecoveryKeys = nil
		for _, key := range newKeys {
			dec, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				t.Fatal(err)
			}
			cluster.RecoveryKeys = append(cluster.RecoveryKeys, dec)
		}
		if err := client.Sys().GenerateRootCancel(); err != nil {
			t.Fatal(err)
		}
		testhelpers.GenerateRoot(t, cluster, testhelpers.GenerateRootRegular)
	}
}

func testSysRotate_Verification(t *testing.T, recovery bool) {
	opts := &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	}

	if recovery {
		opts.SealFunc = func() vault.Seal {
			return vault.NewTestSeal(t, &seal.TestSealOpts{
				StoredKeys: seal.StoredKeysSupportedGeneric,
			})
		}
	}

	inm, err := inmem.NewInmemHA(nil, logging.NewVaultLogger(hclog.Debug))
	require.NoError(t, err)

	conf := vault.CoreConfig{
		Physical: inm,
	}
	cluster := vault.NewTestCluster(t, &conf, opts)
	cluster.Start()
	defer cluster.Cleanup()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client
	client.SetMaxRetries(0)

	initFunc := client.Sys().RotateRootInit
	updateFunc := client.Sys().RotateRootUpdate
	verificationUpdateFunc := client.Sys().RotateRootVerificationUpdate
	verificationStatusFunc := client.Sys().RotateRootVerificationStatus
	verificationCancelFunc := client.Sys().RotateRootVerificationCancel
	if recovery {
		initFunc = client.Sys().RotateRecoveryInit
		updateFunc = client.Sys().RotateRecoveryUpdate
		verificationUpdateFunc = client.Sys().RotateRecoveryVerificationUpdate
		verificationStatusFunc = client.Sys().RotateRecoveryVerificationStatus
		verificationCancelFunc = client.Sys().RotateRecoveryVerificationCancel
	}

	var verificationNonce string
	var newKeys []string
	doRotateInitialSteps := func() {
		status, err := initFunc(&api.RotateInitRequest{
			SecretShares:        5,
			SecretThreshold:     3,
			RequireVerification: true,
		})
		require.NoError(t, err)
		require.NotNil(t, status)
		require.True(t, status.VerificationRequired)

		keys := cluster.BarrierKeys
		if recovery {
			keys = cluster.RecoveryKeys
		}

		var resp *api.RotateUpdateResponse
		for i := range 3 {
			resp, err = updateFunc(base64.StdEncoding.EncodeToString(keys[i]), status.Nonce)
			require.NoError(t, err)
		}

		require.True(t, resp.Complete)
		require.True(t, resp.VerificationRequired)
		require.NotEmpty(t, resp.VerificationNonce)

		verificationNonce = resp.VerificationNonce
		newKeys = resp.KeysB64
		t.Logf("verification nonce: %q", verificationNonce)
	}

	doRotateInitialSteps()

	// We are still going, so should not be able to init again
	_, err = initFunc(&api.RotateInitRequest{
		SecretShares:        5,
		SecretThreshold:     3,
		RequireVerification: true,
	})
	require.Error(t, err)

	// Sealing should clear state, so after this we should be able to perform
	// the above again
	cluster.EnsureCoresSealed(t)
	err = cluster.UnsealCoresWithError(recovery)
	require.NoError(t, err)

	doRotateInitialSteps()

	doStartVerify := func() {
		// Start the process
		for i := range 2 {
			status, err := verificationUpdateFunc(newKeys[i], verificationNonce)
			require.NoError(t, err)
			require.Equalf(t, status.Nonce, verificationNonce, "unexpected nonce, expected %q, got %q", verificationNonce, status.Nonce)
			require.False(t, status.Complete)
		}

		// Check status
		vStatus, err := verificationStatusFunc()
		require.NoError(t, err)
		require.Equalf(t, vStatus.Nonce, verificationNonce, "unexpected nonce, expected %q, got %q", verificationNonce, vStatus.Nonce)
		require.Equal(t, vStatus.T, 3)
		require.Equal(t, vStatus.N, 5)
		require.Equal(t, vStatus.Progress, 2)
	}

	doStartVerify()

	// Cancel; this should still keep the rotation process going but just cancel
	// the verification operation
	err = verificationCancelFunc()
	require.NoError(t, err)

	// Verify cannot init again
	_, err = initFunc(&api.RotateInitRequest{
		SecretShares:        5,
		SecretThreshold:     3,
		RequireVerification: true,
	})
	require.Error(t, err)

	vStatus, err := verificationStatusFunc()
	require.NoError(t, err)
	require.NotEqualf(t, vStatus.Nonce, verificationNonce, "unexpected nonce, expected not-%q but got it", verificationNonce)
	require.Equal(t, vStatus.T, 3)
	require.Equal(t, vStatus.N, 5)
	require.Equal(t, vStatus.Progress, 0)

	verificationNonce = vStatus.Nonce
	doStartVerify()

	if !recovery {
		// Sealing should clear state, but we never actually finished, so it should
		// still be the old keys (which are still currently set)
		cluster.EnsureCoresSealed(t)
		cluster.UnsealCores(t)
		vault.TestWaitActive(t, cluster.Cores[0].Core)

		// Should be able to init again and get back to where we were
		doRotateInitialSteps()
		doStartVerify()
	} else {
		// We haven't finished, so generating a root token should still be the
		// old keys (which are still currently set)
		testhelpers.GenerateRoot(t, cluster, testhelpers.GenerateRootRegular)
	}

	// Provide the final new key
	vuStatus, err := verificationUpdateFunc(newKeys[2], verificationNonce)
	require.NoError(t, err)
	require.Equalf(t, vuStatus.Nonce, verificationNonce, "unexpected nonce, expected %q, got %q", verificationNonce, vuStatus.Nonce)
	require.True(t, vuStatus.Complete)

	if !recovery {
		// Seal and unseal -- it should fail to unseal because the key has now been
		// rotated
		cluster.EnsureCoresSealed(t)

		// Simulate restarting Vault rather than just a seal/unseal, because
		// the standbys may not have had time to learn about the new key before
		// we sealed them. We could sleep, but that's unreliable.
		oldKeys := cluster.BarrierKeys
		opts.SkipInit = true
		opts.SealFunc = nil // post rotation we should use the barrier config on disk
		cluster = vault.NewTestCluster(t, &conf, opts)
		cluster.BarrierKeys = oldKeys
		cluster.Start()
		defer cluster.Cleanup()

		err = cluster.UnsealCoresWithError(false)
		require.Error(t, err)

		// Swap out the keys with our new ones and try again
		var newKeyBytes [][]byte
		for _, key := range newKeys {
			val, err := base64.StdEncoding.DecodeString(key)
			require.NoError(t, err)
			newKeyBytes = append(newKeyBytes, val)
		}
		cluster.BarrierKeys = newKeyBytes
		err := cluster.UnsealCoresWithError(false)
		require.NoError(t, err)
	} else {
		// The old keys should no longer work
		_, err := testhelpers.GenerateRootWithError(t, cluster, testhelpers.GenerateRootRegular)
		require.Error(t, err)

		// Put the new keys in place and run again
		cluster.RecoveryKeys = nil
		for _, key := range newKeys {
			dec, err := base64.StdEncoding.DecodeString(key)
			require.NoError(t, err)
			cluster.RecoveryKeys = append(cluster.RecoveryKeys, dec)
		}
		err = client.Sys().GenerateRootCancel()
		require.NoError(t, err)
		testhelpers.GenerateRoot(t, cluster, testhelpers.GenerateRootRegular)
	}
}
