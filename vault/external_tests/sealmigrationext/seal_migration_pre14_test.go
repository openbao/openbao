// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sealmigrationext

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/helper/testhelpers/teststorage"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/vault/external_tests/sealmigration"
)

func TestSealMigration_ShamirToTransit_Pre14(t *testing.T) {
	t.Parallel()
	logger := logging.NewVaultLogger(hclog.Debug).Named(t.Name())
	storage, cleanup := teststorage.MakeReusableStorage(t, logger,
		teststorage.MakeInmemBackend(t, logger))
	defer cleanup()
	sealmigration.ParamTestSealMigrationShamirToTransit_Pre14(t, logger, storage,
		sealmigration.BasePort_ShamirToTransit_Pre14+300)
}

func TestSealMigration_TransitToShamir_Pre14(t *testing.T) {
	t.Parallel()
	logger := logging.NewVaultLogger(hclog.Debug).Named(t.Name())
	storage, cleanup := teststorage.MakeReusableStorage(t, logger,
		teststorage.MakeInmemBackend(t, logger))
	defer cleanup()
	sealmigration.ParamTestSealMigrationTransitToShamir_Pre14(t, logger, storage,
		sealmigration.BasePort_TransitToShamir_Pre14+300)
}

func TestSealMigration_ShamirToTransit_Post14(t *testing.T) {
	t.Parallel()
	logger := logging.NewVaultLogger(hclog.Debug).Named(t.Name())
	storage, cleanup := teststorage.MakeReusableStorage(t, logger,
		teststorage.MakeInmemBackend(t, logger))
	defer cleanup()
	sealmigration.ParamTestSealMigrationTransitToShamir_Post14(t, logger, storage,
		sealmigration.BasePort_ShamirToTransit_Post14+300)
}

func TestSealMigration_TransitToShamir_Post14(t *testing.T) {
	t.Parallel()
	logger := logging.NewVaultLogger(hclog.Debug).Named(t.Name())
	storage, cleanup := teststorage.MakeReusableStorage(t, logger,
		teststorage.MakeInmemBackend(t, logger))
	defer cleanup()
	sealmigration.ParamTestSealMigrationTransitToShamir_Post14(t, logger, storage,
		sealmigration.BasePort_TransitToShamir_Post14+300)
}

func TestSealMigration_TransitToTransit_Post14(t *testing.T) {
	t.Parallel()
	logger := logging.NewVaultLogger(hclog.Debug).Named(t.Name())
	storage, cleanup := teststorage.MakeReusableStorage(t, logger,
		teststorage.MakeInmemBackend(t, logger))
	defer cleanup()
	sealmigration.ParamTestSealMigration_TransitToTransit(t, logger, storage,
		sealmigration.BasePort_TransitToTransit+300)
}
