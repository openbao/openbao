// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
)

func TestInmemHA(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	f, err := NewInmemHAFactory(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Use the same inmem backend to acquire the same set of locks
	physical.ExerciseHABackend(t, f(0).(physical.HABackend), f(1).(physical.HABackend))
}
