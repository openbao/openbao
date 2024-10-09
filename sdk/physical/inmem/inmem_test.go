// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package inmem

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"
)

func TestInmem(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	inm, err := NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	physical.ExerciseBackend(t, inm)
	physical.ExerciseTransactionalBackend(t, inm.(physical.TransactionalBackend))
	physical.ExerciseBackend_ListPrefix(t, inm)
}
