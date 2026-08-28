package pebbledb

import (
	"testing"

	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical"

	log "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestPebbleDBBackend(t *testing.T) {
	t.Parallel()

	opts := map[string]string{
		"path": ":memory:",
	}

	logger := logging.NewVaultLogger(log.Debug)

	db, err := NewBackend(opts, logger)
	require.NoError(t, err)

	logger.Info("Running basic backend tests")
	physical.ExerciseBackend(t, db)

	logger.Info("Running transactional tests")
	physical.ExerciseTransactionalBackend(t, db.(physical.TransactionalBackend))
}
