package logical

import (
	"context"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/physical/file"
	"github.com/stretchr/testify/assert"
)

var storage Storage
var txStorage Storage

func Setup(t *testing.T) {
	storage = makeStorage(t)
	txStorage = makeTxStorage(t)
}

func TestStartTxStorage(t *testing.T) {
	tests := []struct {
		name           string
		initialStorage Storage
		finalStorage   Storage
	}{
		{
			name:           "successful tx begin",
			initialStorage: storage,
			finalStorage:   txStorage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{Storage: tt.initialStorage}
			rollback, err := StartTxStorage(context.Background(), req)
			assert.NoError(t, err)
			assert.NotNil(t, rollback)
			assert.IsType(t, tt.finalStorage, req.Storage)
			assert.IsType(t, tt.initialStorage, req.OriginalStorage)
			assert.IsType(t, func() {}, rollback)
		})
	}
}

func TestEndTxStorage(t *testing.T) {
	tests := []struct {
		name           string
		initialStorage Storage
		finalStorage   Storage
	}{
		{
			name:           "successful end",
			initialStorage: txStorage,
			finalStorage:   storage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{Storage: tt.initialStorage}
			err := EndTxStorage(context.Background(), req)
			assert.NoError(t, err)
			assert.IsType(t, tt.finalStorage, req.Storage)
			assert.Nil(t, req.OriginalStorage)
		})
	}
}

func makeStorage(t *testing.T) Storage {
	dir := t.TempDir()
	logger := logging.NewVaultLogger(log.Debug)

	b, err := file.NewFileBackend(map[string]string{
		"path": dir,
	}, logger)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return NewLogicalStorage(b)
}

func makeTxStorage(t *testing.T) Storage {
	logicalStorage := makeStorage(t)
	if txStorage, ok := logicalStorage.(TransactionalStorage); ok {
		txn, err := txStorage.BeginTx(context.Background())
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		return txn
	}
	t.Fatalf("storage is not transactional")
	return nil
}
