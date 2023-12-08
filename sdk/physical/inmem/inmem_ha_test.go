// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/lf-edge/openbao/sdk/helper/logging"
	"github.com/lf-edge/openbao/sdk/physical"
)

func TestInmemHA(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmemHA(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Use the same inmem backend to acquire the same set of locks
	physical.ExerciseHABackend(t, inm.(physical.HABackend), inm.(physical.HABackend))
}
