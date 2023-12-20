// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package internal

import (
	"context"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/helper/consts"
	"github.com/openbao/openbao/sdk/logical"
	"github.com/openbao/openbao/vault"
)

type WrappedCoreNodeStatus interface {
	ActiveTime() time.Time
	GetSealStatus(ctx context.Context, lock bool) (*vault.SealStatusResponse, error)
	IsRaftVoter() bool
	ListenerAddresses() ([]string, error)
	LogLevel() string
	ReplicationState() consts.ReplicationState
}

var _ WrappedCoreNodeStatus = &vault.Core{}

type WrappedCoreStandbyStates interface {
	StandbyStates() (bool, bool)
}

var _ WrappedCoreStandbyStates = &vault.Core{}

type WrappedCoreHCPToken interface {
	Sealed() bool
	CreateToken(context.Context, *logical.TokenEntry) error
	WrappedCoreStandbyStates
}

var _ WrappedCoreHCPToken = &vault.Core{}

type WrappedCoreMeta interface {
	NamespaceByID(ctx context.Context, nsID string) (*namespace.Namespace, error)
	ListNamespaces(includePath bool) []*namespace.Namespace
	ListMounts() ([]*vault.MountEntry, error)
	ListAuths() ([]*vault.MountEntry, error)
	HAEnabled() bool
	HAStateWithLock() consts.HAState
	GetHAPeerNodesCached() []vault.PeerNode
	GetRaftConfiguration(ctx context.Context) (*raft.RaftConfigurationResponse, error)
	GetRaftAutopilotState(ctx context.Context) (*raft.AutopilotState, error)
	StorageType() string
	Cluster(ctx context.Context) (*vault.Cluster, error)
}

var _ WrappedCoreMeta = &vault.Core{}

type WrappedCoreHCPLinkStatus interface {
	WrappedCoreStandbyStates
	SetHCPLinkStatus(status, name string)
	GetHCPLinkStatus() (string, string)
}

var _ WrappedCoreHCPLinkStatus = &vault.Core{}
