// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testcluster

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/xor"
)

// Note that OSS standbys will not accept seal requests.  And ent perf standbys
// may fail it as well if they haven't yet been able to get "elected" as perf standbys.
func SealNode(ctx context.Context, cluster VaultCluster, nodeIdx int) error {
	if nodeIdx >= len(cluster.Nodes()) {
		return fmt.Errorf("invalid nodeIdx %d for cluster", nodeIdx)
	}
	node := cluster.Nodes()[nodeIdx]
	client := node.APIClient()

	err := client.Sys().SealWithContext(ctx)
	if err != nil {
		return err
	}

	return NodeSealed(ctx, cluster, nodeIdx)
}

func SealAllNodes(ctx context.Context, cluster VaultCluster) error {
	for i := range cluster.Nodes() {
		if err := SealNode(ctx, cluster, i); err != nil {
			return err
		}
	}
	return nil
}

func UnsealNode(ctx context.Context, cluster VaultCluster, nodeIdx int) error {
	if nodeIdx >= len(cluster.Nodes()) {
		return fmt.Errorf("invalid nodeIdx %d for cluster", nodeIdx)
	}
	node := cluster.Nodes()[nodeIdx]
	client := node.APIClient()

	for _, key := range cluster.GetBarrierOrRecoveryKeys() {
		_, err := client.Sys().UnsealWithContext(ctx, hex.EncodeToString(key))
		if err != nil {
			return err
		}
	}

	return NodeHealthy(ctx, cluster, nodeIdx)
}

func UnsealAllNodes(ctx context.Context, cluster VaultCluster) error {
	for i := range cluster.Nodes() {
		if err := UnsealNode(ctx, cluster, i); err != nil {
			return err
		}
	}
	return nil
}

func NodeSealed(ctx context.Context, cluster VaultCluster, nodeIdx int) error {
	if nodeIdx >= len(cluster.Nodes()) {
		return fmt.Errorf("invalid nodeIdx %d for cluster", nodeIdx)
	}
	node := cluster.Nodes()[nodeIdx]
	client := node.APIClient()

	var health *api.HealthResponse
	var err error
	for ctx.Err() == nil {
		health, err = client.Sys().HealthWithContext(ctx)
		switch {
		case err != nil:
		case !health.Sealed:
			err = fmt.Errorf("unsealed: %#v", health)
		default:
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("node %d is not sealed: %v", nodeIdx, err)
}

func WaitForNCoresSealed(ctx context.Context, cluster VaultCluster, n int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error)
	for i := range cluster.Nodes() {
		go func(i int) {
			var err error
			for ctx.Err() == nil {
				err = NodeSealed(ctx, cluster, i)
				if err == nil {
					errs <- nil
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err == nil {
				err = ctx.Err()
			}
			errs <- err
		}(i)
	}

	var merr *multierror.Error
	var sealed int
	for range cluster.Nodes() {
		err := <-errs
		if err != nil {
			merr = multierror.Append(merr, err)
		} else {
			sealed++
			if sealed == n {
				return nil
			}
		}
	}

	return fmt.Errorf("%d cores were not sealed, errs: %v", n, merr.ErrorOrNil())
}

func NodeHealthy(ctx context.Context, cluster VaultCluster, nodeIdx int) error {
	if nodeIdx >= len(cluster.Nodes()) {
		return fmt.Errorf("invalid nodeIdx %d for cluster", nodeIdx)
	}
	node := cluster.Nodes()[nodeIdx]
	client := node.APIClient()

	var health *api.HealthResponse
	var err error
	for ctx.Err() == nil {
		health, err = client.Sys().HealthWithContext(ctx)
		switch {
		case err != nil:
		case health == nil:
			err = errors.New("nil response to health check")
		case health.Sealed:
			err = fmt.Errorf("sealed: %#v", health)
		default:
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("node %d is unhealthy: %v", nodeIdx, err)
}

func LeaderNode(ctx context.Context, cluster VaultCluster) (int, error) {
	// Be robust to multiple nodes thinking they are active. This is possible in
	// certain network partition situations where the old leader has not
	// discovered it's lost leadership yet. In tests this is only likely to come
	// up when we are specifically provoking it, but it's possible it could happen
	// at any point if leadership flaps of connectivity suffers transient errors
	// etc. so be robust against it. The best solution would be to have some sort
	// of epoch like the raft term that is guaranteed to be monotonically
	// increasing through elections, however we don't have that abstraction for
	// all HABackends in general. The best we have is the ActiveTime. In a
	// distributed systems text book this would be bad to rely on due to clock
	// sync issues etc. but for our tests it's likely fine because even if we are
	// running separate Vault containers, they are all using the same hardware
	// clock in the system.
	leaderActiveTimes := make(map[int]time.Time)
	for i, node := range cluster.Nodes() {
		client := node.APIClient()
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		resp, err := client.Sys().LeaderWithContext(ctx)
		cancel()
		if err != nil || resp == nil || !resp.IsSelf {
			continue
		}
		leaderActiveTimes[i] = resp.ActiveTime
	}
	if len(leaderActiveTimes) == 0 {
		return -1, errors.New("no leader found")
	}
	// At least one node thinks it is active. If multiple, pick the one with the
	// most recent ActiveTime. Note if there is only one then this just returns
	// it.
	var newestLeaderIdx int
	var newestActiveTime time.Time
	for i, at := range leaderActiveTimes {
		if at.After(newestActiveTime) {
			newestActiveTime = at
			newestLeaderIdx = i
		}
	}
	return newestLeaderIdx, nil
}

func WaitForActiveNode(ctx context.Context, cluster VaultCluster) (int, error) {
	for ctx.Err() == nil {
		if idx, _ := LeaderNode(ctx, cluster); idx != -1 {
			return idx, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return -1, ctx.Err()
}

type GenerateRootKind int

const (
	GenerateRootRegular GenerateRootKind = iota
	GenerateRecovery    GenerateRootKind = iota + 1
)

func GenerateRoot(cluster VaultCluster, kind GenerateRootKind) (string, error) {
	// If recovery keys supported, use those to perform root token generation instead
	keys := cluster.GetBarrierOrRecoveryKeys()

	client := cluster.Nodes()[0].APIClient()

	var err error
	var status *api.GenerateRootStatusResponse
	switch kind {
	case GenerateRootRegular:
		status, err = client.Sys().GenerateRootInit("", "")
	case GenerateRecovery:
		status, err = client.Sys().GenerateRecoveryOperationTokenInit("", "")

	}
	if err != nil {
		return "", err
	}

	if status.Required > len(keys) {
		return "", fmt.Errorf("need more keys than have, need %d have %d", status.Required, len(keys))
	}

	otp := status.OTP

	for i, key := range keys {
		if i >= status.Required {
			break
		}

		strKey := base64.StdEncoding.EncodeToString(key)
		switch kind {
		case GenerateRootRegular:
			status, err = client.Sys().GenerateRootUpdate(strKey, status.Nonce)
		case GenerateRecovery:
			status, err = client.Sys().GenerateRecoveryOperationTokenUpdate(strKey, status.Nonce)
		}
		if err != nil {
			return "", err
		}
	}
	if !status.Complete {
		return "", errors.New("generate root operation did not end successfully")
	}

	tokenBytes, err := base64.RawStdEncoding.DecodeString(status.EncodedToken)
	if err != nil {
		return "", err
	}
	tokenBytes, err = xor.XORBytes(tokenBytes, []byte(otp))
	if err != nil {
		return "", err
	}
	return string(tokenBytes), nil
}
