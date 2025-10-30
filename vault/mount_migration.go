// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/namespace"
)

type MountMigrationStatus int

const (
	MigrationInProgressStatus MountMigrationStatus = iota
	MigrationSuccessStatus
	MigrationFailureStatus
)

func (m MountMigrationStatus) String() string {
	switch m {
	case MigrationInProgressStatus:
		return "in-progress"
	case MigrationSuccessStatus:
		return "success"
	case MigrationFailureStatus:
		return "failure"
	}
	return "unknown"
}

type MountMigrationInfo struct {
	SourceMount     string `json:"source_mount"`
	TargetMount     string `json:"target_mount"`
	MigrationStatus string `json:"status"`
}

func (c *Core) createMigrationStatus(from, to namespace.MountPathDetails) (string, error) {
	migrationID, err := uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("error generating uuid for mount move invocation: %w", err)
	}
	migrationInfo := MountMigrationInfo{
		SourceMount:     from.Namespace.Path + from.MountPath,
		TargetMount:     to.Namespace.Path + to.MountPath,
		MigrationStatus: MigrationInProgressStatus.String(),
	}
	c.mountMigrationTracker.Store(migrationID, migrationInfo)
	return migrationID, nil
}

func (c *Core) setMigrationStatus(migrationID string, migrationStatus MountMigrationStatus) error {
	migrationInfoRaw, ok := c.mountMigrationTracker.Load(migrationID)
	if !ok {
		return fmt.Errorf("migration Tracker entry missing for ID %s", migrationID)
	}
	migrationInfo := migrationInfoRaw.(MountMigrationInfo)
	migrationInfo.MigrationStatus = migrationStatus.String()
	c.mountMigrationTracker.Store(migrationID, migrationInfo)
	return nil
}

func (c *Core) readMigrationStatus(migrationID string) *MountMigrationInfo {
	migrationInfoRaw, ok := c.mountMigrationTracker.Load(migrationID)
	if !ok {
		return nil
	}
	migrationInfo := migrationInfoRaw.(MountMigrationInfo)
	return &migrationInfo
}
