// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package quotas

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestQuotas_MountPathOverwrite(t *testing.T) {
	qm, err := NewManager(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink(), true)
	require.NoError(t, err)

	quota := NewRateLimitQuota("tq", "", "kv1/", "", "", 10, time.Second, 0, false)
	require.NoError(t, qm.SetQuota(context.Background(), TypeRateLimit.String(), quota, false))
	quota = quota.Clone().(*RateLimitQuota)
	quota.MountPath = "kv2/"
	require.NoError(t, qm.SetQuota(context.Background(), TypeRateLimit.String(), quota, false))

	q, err := qm.QueryQuota(&Request{
		Type:      TypeRateLimit,
		MountPath: "kv1/",
	})
	require.NoError(t, err)
	require.Nil(t, q)

	require.NoError(t, qm.DeleteQuota(context.Background(), TypeRateLimit.String(), "tq"))

	q, err = qm.QueryQuota(&Request{
		Type:      TypeRateLimit,
		MountPath: "kv1/",
	})
	require.NoError(t, err)
	require.Nil(t, q)
}

func TestQuotas_Precedence(t *testing.T) {
	qm, err := NewManager(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink(), true)
	require.NoError(t, err)

	setQuotaFunc := func(t *testing.T, name, nsPath, mountPath, pathSuffix, role string) Quota {
		t.Helper()
		quota := NewRateLimitQuota(name, nsPath, mountPath, pathSuffix, role, 10, time.Second, 0, false)
		require.NoError(t, qm.SetQuota(context.Background(), TypeRateLimit.String(), quota, true))
		return quota
	}

	checkQuotaFunc := func(t *testing.T, nsPath, mountPath, pathSuffix, role string, expected Quota) {
		t.Helper()
		quota, err := qm.QueryQuota(&Request{
			Type:          TypeRateLimit,
			NamespacePath: nsPath,
			MountPath:     mountPath,
			Role:          role,
			Path:          nsPath + mountPath + pathSuffix,
		})
		require.NoError(t, err)

		if diff := deep.Equal(expected, quota); len(diff) > 0 {
			t.Fatal(diff)
		}
	}

	// No quota present. Expect nil.
	checkQuotaFunc(t, "", "", "", "", nil)

	// Define global quota and expect that to be returned.
	rateLimitGlobalQuota := setQuotaFunc(t, "rateLimitGlobalQuota", "", "", "", "")
	checkQuotaFunc(t, "", "", "", "", rateLimitGlobalQuota)

	// Define a global mount specific quota and expect that to be returned.
	rateLimitGlobalMountQuota := setQuotaFunc(t, "rateLimitGlobalMountQuota", "", "testmount/", "", "")
	checkQuotaFunc(t, "", "testmount/", "", "", rateLimitGlobalMountQuota)

	// Define a global mount + path specific quota and expect that to be returned.
	rateLimitGlobalMountPathQuota := setQuotaFunc(t, "rateLimitGlobalMountPathQuota", "", "testmount/", "testpath", "")
	checkQuotaFunc(t, "", "testmount/", "testpath", "", rateLimitGlobalMountPathQuota)

	// Define a namespace quota and expect that to be returned.
	rateLimitNSQuota := setQuotaFunc(t, "rateLimitNSQuota", "testns/", "", "", "")
	checkQuotaFunc(t, "testns/", "", "", "", rateLimitNSQuota)

	// Define a namespace mount specific quota and expect that to be returned.
	rateLimitNSMountQuota := setQuotaFunc(t, "rateLimitNSMountQuota", "testns/", "testmount/", "", "")
	checkQuotaFunc(t, "testns/", "testmount/", "testpath", "", rateLimitNSMountQuota)

	// Define a namespace mount + glob and expect that to be returned.
	rateLimitNSMountGlob := setQuotaFunc(t, "rateLimitNSMountGlob", "testns/", "testmount/", "*", "")
	checkQuotaFunc(t, "testns/", "testmount/", "testpath", "", rateLimitNSMountGlob)

	// Define a namespace mount + path specific quota with a glob and expect that to be returned.
	rateLimitNSMountPathSuffixGlob := setQuotaFunc(t, "rateLimitNSMountPathSuffixGlob", "testns/", "testmount/", "test*", "")
	checkQuotaFunc(t, "testns/", "testmount/", "testpath", "", rateLimitNSMountPathSuffixGlob)

	// Define a namespace mount + path specific quota with a glob at the end of the path and expect that to be returned.
	rateLimitNSMountPathSuffixGlobAfterPath := setQuotaFunc(t, "rateLimitNSMountPathSuffixGlobAfterPath", "testns/", "testmount/", "testpath*", "")
	checkQuotaFunc(t, "testns/", "testmount/", "testpath", "", rateLimitNSMountPathSuffixGlobAfterPath)

	// Define a namespace mount + path specific quota and expect that to be returned.
	rateLimitNSMountPathQuota := setQuotaFunc(t, "rateLimitNSMountPathQuota", "testns/", "testmount/", "testpath", "")
	checkQuotaFunc(t, "testns/", "testmount/", "testpath", "", rateLimitNSMountPathQuota)

	// Define a namespace mount + role specific quota and expect that to be returned.
	rateLimitNSMountRoleQuota := setQuotaFunc(t, "rateLimitNSMountPathQuota", "testns/", "testmount/", "", "role")
	checkQuotaFunc(t, "testns/", "testmount/", "", "role", rateLimitNSMountRoleQuota)

	// Now that many quota types are defined, verify that the most specific
	// matches are returned per namespace.
	checkQuotaFunc(t, "", "", "", "", rateLimitGlobalQuota)
	checkQuotaFunc(t, "testns/", "", "", "", rateLimitNSQuota)
}

// TestQuotas_QueryRoleQuotas checks to see if quota creation on a mount
// requires a call to ResolveRoleOperation.
func TestQuotas_QueryResolveRole_RateLimitQuotas(t *testing.T) {
	qm, err := NewManager(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink(), true)
	require.NoError(t, err)

	rlqReq := &Request{
		Type:          TypeRateLimit,
		Path:          "",
		MountPath:     "mount1/",
		NamespacePath: "",
		ClientAddress: "127.0.0.1",
	}
	// Check that we have no quotas requiring role resolution on mount1/
	required, err := qm.QueryResolveRoleQuotas(rlqReq)
	require.NoError(t, err)
	require.False(t, required)

	// Create a non-role-based RLQ on mount1/ and make sure it doesn't require role resolution
	rlq := NewRateLimitQuota("tq", rlqReq.NamespacePath, rlqReq.MountPath, rlqReq.Path, rlqReq.Role, 10, 1*time.Minute, 10*time.Second, false)
	require.NoError(t, qm.SetQuota(context.Background(), TypeRateLimit.String(), rlq, false))

	required, err = qm.QueryResolveRoleQuotas(rlqReq)
	require.NoError(t, err)
	require.False(t, required)

	// Create a role-based RLQ on mount1/ and make sure it requires role resolution
	rlqReq.Role = "test"
	rlq = NewRateLimitQuota("tq", rlqReq.NamespacePath, rlqReq.MountPath, rlqReq.Path, rlqReq.Role, 10, 1*time.Minute, 10*time.Second, false)
	require.NoError(t, qm.SetQuota(context.Background(), TypeRateLimit.String(), rlq, false))

	required, err = qm.QueryResolveRoleQuotas(rlqReq)
	require.NoError(t, err)
	require.True(t, required)

	// Check that we have no quotas requiring role resolution on mount2/
	rlqReq.MountPath = "mount2/"
	required, err = qm.QueryResolveRoleQuotas(rlqReq)
	require.NoError(t, err)
	require.False(t, required)
}

func TestQuotas_HandleNamespaceDeletion(t *testing.T) {
	qm, err := NewManager(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink(), true)
	require.NoError(t, err)

	err = qm.Setup(context.Background(), new(logical.InmemStorage))
	require.NoError(t, err)

	rlqs := []*RateLimitQuota{
		NewRateLimitQuota("namespace-only", "foo/", "", "", "", 10, time.Minute, time.Second, false),
		NewRateLimitQuota("namespace-mount", "foo/", "sys/", "", "", 10, time.Minute, time.Second, false),
	}

	for _, rlq := range rlqs {
		err := qm.SetQuota(context.Background(), TypeRateLimit.String(), rlq, false)
		require.NoError(t, err)
	}

	err = qm.HandleNamespaceDeletion(context.Background(), "foo/")
	require.NoError(t, err)

	q, err := qm.QuotaByName(TypeRateLimit.String(), "namespace-only")
	require.NoError(t, err)
	require.Nil(t, q)

	// Should still be there, handled by HandleBackendDisabling.
	q, err = qm.QuotaByName(TypeRateLimit.String(), "namespace-mount")
	require.NoError(t, err)
	require.NotNil(t, q)
}

func TestQuotas_HandleBackendDisabling(t *testing.T) {
	qm, err := NewManager(logging.NewVaultLogger(log.Trace), metricsutil.BlackholeSink(), true)
	require.NoError(t, err)

	err = qm.Setup(context.Background(), new(logical.InmemStorage))
	require.NoError(t, err)

	rlqs := []*RateLimitQuota{
		NewRateLimitQuota("namespace-only", "foo/", "", "", "", 10, time.Minute, time.Second, false),
		NewRateLimitQuota("namespace-mount", "foo/", "sys/", "", "", 10, time.Minute, time.Second, false),
		NewRateLimitQuota("namespace-mount-path", "foo/", "sys/", "policies/", "", 10, time.Minute, time.Second, false),
		NewRateLimitQuota("namespace-mount-role", "foo/", "sys/", "", "bob", 10, time.Minute, time.Second, false),
	}

	for _, rlq := range rlqs {
		err := qm.SetQuota(context.Background(), TypeRateLimit.String(), rlq, false)
		require.NoError(t, err)
	}

	err = qm.HandleBackendDisabling(context.Background(), "foo/", "sys/")
	require.NoError(t, err)

	for _, name := range []string{"namespace-mount", "namespace-mount-path", "namespace-mount-role"} {
		q, err := qm.QuotaByName(TypeRateLimit.String(), name)
		require.NoError(t, err)
		require.Nil(t, q)
	}

	// Should not be deleted by HandleBackendDisabling, but by HandleNamespaceDeletion.
	q, err := qm.QuotaByName(TypeRateLimit.String(), "namespace-only")
	require.NoError(t, err)
	require.NotNil(t, q)
}
