// See /physical/crosstest but with the following difference: this tests
// logical.Storage rather than physical.Backend.
package crosstest

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armon/go-metrics"
	"github.com/go-test/deep"
	log "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	"github.com/openbao/openbao/physical/postgresql"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/helper/logging"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/file"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault"
)

const (
	opsLogFile   = "/tmp/openbao-storage-random-ops.json"
	txOpsLogFile = "/tmp/openbao-storage-random-tx-ops.json"
	numOps       = 1000
	numTxOps     = numOps
)

func Test_ExerciseBackends(t *testing.T) {
	t.Parallel()

	backends, cleanup := allLogical(t)
	defer cleanup()

	exerciseBackends(t, backends)

	// If any were transactions, let's rollback. We can't commit them as
	// we wrote to the same area of storage in lots of places.
	for name, backend := range backends {
		if txn, ok := backend.(logical.Transaction); ok {
			err := txn.Rollback(context.Background())
			require.NoError(t, err, "failed to rollback transaction: %v", name)
		}
	}
}

func Test_RandomOpsBackends(t *testing.T) {
	t.Parallel()

	backends, cleanup := allLogical(t)
	defer cleanup()

	ops := getRandomOps(t, numOps, false, 0)
	// ops := replayOps(t, opsLogFile)
	executeRandomOps(t, backends, ops)
}

func Test_RandomOpsTransactionalBackends(t *testing.T) {
	t.Parallel()

	backends, cleanup := allTransactionalLogical(t)
	defer cleanup()

	txLimit := 10
	ops := getRandomOps(t, numTxOps, true, txLimit)
	executeRandomTransactionalOps(t, backends, ops, txLimit)
}

func Test_ExerciseTransactionalBackends(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	backends, cleanup := allTransactionalLogical(t)
	defer cleanup()

	// Create transactions and exercise the backend, rolling them back.
	txns := make(map[string]logical.Storage, 2*len(backends))
	for name, backend := range backends {
		txn, err := backend.BeginTx(ctx)
		require.NoError(t, err, "failed to create write transaction: %v", name)
		txns[fmt.Sprintf("%v-tx-rw", name)] = txn

		ro_txn, err := backend.BeginTx(ctx)
		require.NoError(t, err, "failed to create read-only transaction: %v", name)
		txns[fmt.Sprintf("%v-tx-ro", name)] = ro_txn
	}

	exerciseBackends(t, txns)

	for name, txn := range txns {
		err := txn.(logical.Transaction).Rollback(ctx)
		require.NoError(t, err, "failed to rollback transaction: %v", name)
	}

	// Ensure we can do a single read/write transactions and commit them.
	// This will leave us with an empty state, but potentially entries in
	// any transaction logs.
	txns = make(map[string]logical.Storage, len(backends))
	for name, backend := range backends {
		txn, err := backend.BeginTx(ctx)
		require.NoError(t, err, "failed to create write transaction: %v", name)
		txns[fmt.Sprintf("%v-tx-rw", name)] = txn
	}

	exerciseBackends(t, txns)

	for name, txn := range txns {
		err := txn.(logical.Transaction).Commit(ctx)
		require.NoError(t, err, "failed to commit transaction: %v", name)
	}

	// Finally, exercise transactions.
	exerciseTransactions(t, backends)
}

func getFile(t *testing.T, logger log.Logger) (physical.Backend, func()) {
	backendPath, err := os.MkdirTemp("", "vault")
	require.NoError(t, err, "error while creating file storage")

	b, err := file.NewFileBackend(map[string]string{
		"path": backendPath,
	}, logger)
	require.NoError(t, err, "error while initializing file backend")

	return b, func() {
		os.RemoveAll(backendPath)
	}
}

func allLogical(t *testing.T) (map[string]logical.Storage, func()) {
	ctx := context.Background()
	logger := logging.NewVaultLogger(log.Debug)
	disableTxConf := map[string]string{"disable_transactions": "true"}

	// Basic storage backends.

	// raft, no transaction called on it.
	prb, raftPureDir := raft.GetRaft(t, true, true)

	// raft
	rb, raftDir := raft.GetRaft(t, true, true)

	// raft-in-tx
	//
	// Inside a raft transaction should behave the same as outside
	// if it is writable. We are fine to reuse the same raft instance
	// here as the transaction should not see stuff created after it.
	rt, err := rb.BeginTx(ctx)
	require.NoError(t, err, "failed to start raft transaction")

	// file
	fb, fileCleanup := getFile(t, logger)

	// inmem
	inm, err := inmem.NewInmem(disableTxConf, logger)
	require.NoError(t, err, "failed to create in-memory backend")

	// txinmem
	_txinm, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-memory backend")
	txinm := _txinm.(physical.TransactionalBackend)

	// postgres
	psql, psqlCleanup := postgresql.GetTestPostgreSQLBackend(t, logger)

	return map[string]logical.Storage{
			"pure-raft": logical.NewLogicalStorage(prb),

			"raft":       logical.NewLogicalStorage(rb),
			"raft-in-tx": logical.NewLogicalStorage(rt),
			"file":       logical.NewLogicalStorage(fb),

			"inmem":               new(logical.InmemStorage),
			"inmem-via-wrapper":   logical.NewLogicalStorage(inm),
			"txinmem-via-wrapper": logical.NewLogicalStorage(txinm),

			"psql": logical.NewLogicalStorage(psql),
		}, func() {
			os.RemoveAll(raftPureDir)
			os.RemoveAll(raftDir)
			fileCleanup()
			psqlCleanup()
		}
}

func newAESBarrier(t *testing.T, parent physical.Backend) vault.SecurityBarrier {
	b, err := vault.NewAESGCMBarrier(parent)
	require.NoError(t, err, "failed wrapping parent in AES-GCM barrier")

	key, err := b.GenerateKey(crand.Reader)
	require.NoError(t, err, "failed generating random key")

	b.Initialize(context.Background(), key, nil, crand.Reader)
	b.Unseal(context.Background(), key)

	return b
}

func allTransactionalLogical(t *testing.T) (map[string]logical.TransactionalStorage, func()) {
	logger := logging.NewVaultLogger(log.Debug)

	// Basic storage backends.

	// raft
	rb, raftDir := raft.GetRaft(t, true, true)

	// inmem
	im, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem")

	// inmem+storage-view
	imsv, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem for storage view")
	svim := logical.NewStorageView(logical.NewLogicalStorage(imsv), "my-prefix/")

	// inmem+aes+sv -- this pollutes the global namespace (with core/) so hide it under a storage view
	imasv, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem for AES-GCM with storage view")
	aimsv := newAESBarrier(t, imasv)
	svaim := logical.NewStorageView(aimsv, "prefix-for-testing/")

	// inmem+aes+bv
	imabv, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem for AES-GCM with barrier view")
	aimbv := newAESBarrier(t, imabv)
	bvaim := vault.NewBarrierView(aimbv, "prefix-for-testing/")

	// inmem+cache+encoding+aes+bv
	imceabv, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem for AES-GCM with barrier view")
	cimeabv := physical.NewCache(imceabv, 0, logger, &metrics.BlackholeSink{})
	eimcabv := physical.NewStorageEncoding(cimeabv)
	aimcebv := newAESBarrier(t, eimcabv)
	bvimcae := vault.NewBarrierView(aimcebv, "prefix-for-testing/")

	// raft+cache+encoding+aes+bv
	rceabv, raftFullDir := raft.GetRaft(t, true, true)
	require.NoError(t, err, "failed to create transactional in-mem for AES-GCM with barrier view")
	creabv := physical.NewCache(rceabv, 0, logger, &metrics.BlackholeSink{})
	ercabv := physical.NewStorageEncoding(creabv)
	arcebv := newAESBarrier(t, ercabv)
	bvrcae := vault.NewBarrierView(arcebv, "prefix-for-testing/")

	return map[string]logical.TransactionalStorage{
			"raft":                        logical.NewLogicalStorage(rb).(logical.TransactionalStorage),
			"txinmem":                     logical.NewLogicalStorage(im).(logical.TransactionalStorage),
			"inmem+sv":                    svim.(logical.TransactionalStorage),
			"inmem+aes+sv":                svaim.(logical.TransactionalStorage),
			"inmem+aes+bv":                bvaim.(logical.TransactionalStorage),
			"inmem+cache+encoding+aes+bv": bvimcae.(logical.TransactionalStorage),
			"raft+cache+encoding+aes+bv":  bvrcae.(logical.TransactionalStorage),
		}, func() {
			os.RemoveAll(raftDir)
			os.RemoveAll(raftFullDir)
		}
}

func allDoList(t *testing.T, backends map[string]logical.Storage, prefix string) (map[string][]string, map[string]error) {
	results := make(map[string][]string, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.List(context.Background(), prefix)
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoListPage(t *testing.T, backends map[string]logical.Storage, prefix string, after string, limit int) (map[string][]string, map[string]error) {
	results := make(map[string][]string, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.ListPage(context.Background(), prefix, after, limit)
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoDelete(t *testing.T, backends map[string]logical.Storage, key string) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		err := backend.Delete(context.Background(), key)
		errs[name] = err
	}

	return errs
}

func allDoPut(t *testing.T, backends map[string]logical.Storage, key string, value []byte) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		// Other entry fields are unnecessary.
		err := backend.Put(context.Background(), &logical.StorageEntry{
			Key:   key,
			Value: value,
		})
		errs[name] = err
	}

	return errs
}

func allDoGet(t *testing.T, backends map[string]logical.Storage, key string) (map[string]*logical.StorageEntry, map[string]error) {
	results := make(map[string]*logical.StorageEntry, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.Get(context.Background(), key)
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

// Results are logical.Storage to allow for passing to above allDoX methods.
func allDoBeginTx(t *testing.T, backends map[string]logical.TransactionalStorage) (map[string]logical.Storage, map[string]error) {
	results := make(map[string]logical.Storage, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.BeginTx(context.Background())
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoBeginReadOnlyTx(t *testing.T, backends map[string]logical.TransactionalStorage) (map[string]logical.Storage, map[string]error) {
	results := make(map[string]logical.Storage, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.BeginReadOnlyTx(context.Background())
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoCommit(t *testing.T, backends map[string]logical.Storage) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		tx := backend.(logical.Transaction)
		err := tx.Commit(context.Background())
		errs[name] = err
	}

	return errs
}

func allDoRollback(t *testing.T, backends map[string]logical.Storage) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		tx := backend.(logical.Transaction)
		err := tx.Rollback(context.Background())
		errs[name] = err
	}

	return errs
}

func allDoSameListNoBenchmark(t *testing.T, backends map[string]logical.Storage, prefix string, shouldError bool) {
	results, errs := allDoList(t, backends, prefix)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing LIST with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing LIST with backend %v", name)
		}
	}

	var expected []string
	var expectedName string
	for name, result := range results {
		if expectedName == "" {
			expected = result
			expectedName = name
			continue
		}

		// Ignore the difference between nil and an empty list. This
		// trips up the file backend, where everyone else returns nil
		// after deletion of an entry, but file returns an empty list.
		if len(expected) == 0 && len(result) == 0 {
			continue
		}

		if diff := deep.Equal(expected, result); diff != nil {
			require.Nil(t, diff, "different LIST results between %v and %v:\n====%v (%v items)====\n\t%v\n====%v (%v items)====\n\t%v\n==== diff ====\n%v", expectedName, name, expectedName, len(expected), strings.Join(expected, "\n\t"), name, len(result), strings.Join(result, "\n\t"), diff)
		}
	}
}

func allDoSameList(t *testing.T, backends map[string]logical.Storage, prefix string, expected []string, shouldError bool) {
	results, errs := allDoList(t, backends, prefix)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing LIST with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing LIST with backend %v", name)
		}
	}

	for name, result := range results {
		// Ignore the difference between nil and an empty list. This
		// trips up the file backend, where everyone else returns nil
		// after deletion of an entry, but file returns an empty list.
		if len(expected) == 0 && len(result) == 0 {
			continue
		}

		if diff := deep.Equal(expected, result); diff != nil {
			require.Nil(t, diff, "different LIST results between %v and %v:\n====%v====\n\t%v\n====%v====\n\t%v\n==== diff ====\n%v\n==== results ====\n%v\n", "expected", name, "expected", strings.Join(expected, "\n\t"), name, strings.Join(result, "\n\t"), diff, results)
		}
	}
}

func allDoSameListPageNoBenchmark(t *testing.T, backends map[string]logical.Storage, prefix string, after string, limit int, shouldError bool) {
	results, errs := allDoListPage(t, backends, prefix, after, limit)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing LIST-PAGE with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing LIST-PAGE with backend %v", name)
		}
	}

	var expected []string
	var expectedName string
	for name, result := range results {
		if expectedName == "" {
			expected = result
			expectedName = name
			continue
		}

		// Ignore the difference between nil and an empty list. This
		// trips up the file backend, where everyone else returns nil
		// after deletion of an entry, but file returns an empty list.
		if len(expected) == 0 && len(result) == 0 {
			continue
		}

		if diff := deep.Equal(expected, result); diff != nil {
			require.Nil(t, diff, "different LIST-PAGE results between %v and %v:\n====%v====\n\t%v\n====%v====\n\t%v\n==== diff ====\n%v\n==== results ====\n%v\n", expectedName, name, expectedName, strings.Join(expected, "\n\t"), name, strings.Join(result, "\n\t"), diff, results)
		}
	}
}

func allDoSameListPage(t *testing.T, backends map[string]logical.Storage, prefix string, after string, limit int, expected []string, shouldError bool) {
	results, errs := allDoListPage(t, backends, prefix, after, limit)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing LIST PAGE with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing LIST PAGE with backend %v", name)
		}
	}

	for name, result := range results {
		// Ignore the difference between nil and an empty list. This
		// trips up the file backend, where everyone else returns nil
		// after deletion of an entry, but file returns an empty list.
		if len(expected) == 0 && len(result) == 0 {
			continue
		}

		if diff := deep.Equal(expected, result); diff != nil {
			require.Nil(t, diff, "different LIST PAGE results between %v and %v:\n====%v====\n\t%v\n====%v====\n\t%v\n==== diff ====\n%v", "expected", name, "expected", strings.Join(expected, "\n\t"), name, strings.Join(result, "\n\t"), diff)
		}
	}
}

func allDoSameDelete(t *testing.T, backends map[string]logical.Storage, key string, shouldError bool) {
	errs := allDoDelete(t, backends, key)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing DELETE with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing DELETE with backend %v", name)
		}
	}
}

func allDoSameGetNoBenchmark(t *testing.T, backends map[string]logical.Storage, key string, shouldError bool) {
	results, errs := allDoGet(t, backends, key)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing GET with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing GET with backend %v", name)
		}
	}

	var expected *logical.StorageEntry
	var expectedName string
	for name, result := range results {
		if expectedName == "" {
			expected = result
			expectedName = name
			continue
		}

		if diff := deep.Equal(expected, result); diff != nil {
			require.Nil(t, diff, "different GET results between %v and %v:\n====%v====\n\t%v\n====%v====\n\t%v\n==== diff ====\n%v\n==== results ====\n%v\n", expectedName, name, expectedName, expected, name, result, diff, results)
		}
	}
}

func allDoSameGet(t *testing.T, backends map[string]logical.Storage, key string, expected *logical.StorageEntry, shouldError bool) {
	results, errs := allDoGet(t, backends, key)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing GET with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing GET with backend %v", name)
		}
	}

	for name, result := range results {
		if diff := deep.Equal(expected, result); diff != nil {
			require.Nil(t, diff, "different GET results between %v and %v:\n====%v====\n\t%v\n====%v====\n\t%v\n==== diff ====\n%v", "expected", name, "expected", expected, name, result, diff)
		}
	}
}

func allDoSamePut(t *testing.T, backends map[string]logical.Storage, key string, value []byte, shouldError bool) {
	errs := allDoPut(t, backends, key, value)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing PUT with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing PUT with backend %v", name)
		}
	}
}

func allDoSameBeginTx(t *testing.T, backends map[string]logical.TransactionalStorage, shouldError bool) map[string]logical.Storage {
	results, errs := allDoBeginTx(t, backends)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing BeginTx with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing BeginTx with backend %v", name)
		}
	}

	return results
}

func allDoSameBeginReadOnlyTx(t *testing.T, backends map[string]logical.TransactionalStorage, shouldError bool) map[string]logical.Storage {
	results, errs := allDoBeginReadOnlyTx(t, backends)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing BeginTx with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing BeginTx with backend %v", name)
		}
	}

	return results
}

func allDoSameCommit(t *testing.T, txns map[string]logical.Storage, shouldError bool) {
	errs := allDoCommit(t, txns)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing Commit with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing Commit with backend %v", name)
		}
	}
}

func allDoSameRollback(t *testing.T, txns map[string]logical.Storage, shouldError bool) {
	errs := allDoRollback(t, txns)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing Rollback with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing Rollback with backend %v", name)
		}
	}
}

// This mirrors physical.ExerciseBackends, but applied to many backends in
// parallel to ensure no discernible differences exist between them.
func exerciseBackends(t *testing.T, backends map[string]logical.Storage) {
	// Empty string should be the root.
	allDoSameList(t, backends, "", nil, false)
	allDoSameListPage(t, backends, "", "", -1, nil, false)
	allDoSameListPage(t, backends, "", "asdf", -1, nil, false)
	allDoSameListPage(t, backends, "", "asdf", 11, nil, false)

	// Delete should work if it doesn't exist.
	allDoSameDelete(t, backends, "foo", false)

	// Get should not fail, but be nil.
	allDoSameGet(t, backends, "foo", nil, false)

	// Put should create an entry.
	testString := []byte("test")
	allDoSamePut(t, backends, "foo", testString, false)

	// Get should immediately see this entry.
	allDoSameGet(t, backends, "foo", &logical.StorageEntry{Key: "foo", Value: testString}, false)

	// List should see this entry.
	allDoSameList(t, backends, "", []string{"foo"}, false)
	allDoSameListPage(t, backends, "", "", -1, []string{"foo"}, false)
	allDoSameListPage(t, backends, "", "asdf", -1, []string{"foo"}, false)
	allDoSameListPage(t, backends, "", "asdf", 11, []string{"foo"}, false)

	// Delete should work.
	allDoSameDelete(t, backends, "foo", false)

	// List should no longer see this entry.
	allDoSameList(t, backends, "", nil, false)
	allDoSameListPage(t, backends, "", "", -1, nil, false)
	allDoSameListPage(t, backends, "", "asdf", -1, nil, false)
	allDoSameListPage(t, backends, "", "asdf", 11, nil, false)

	// Get should not fail, but be nil again.
	allDoSameGet(t, backends, "foo", nil, false)

	// Repeated puts to the same entry with the same value should
	// succeed.
	allDoSamePut(t, backends, "foo", testString, false)
	allDoSamePut(t, backends, "foo", testString, false)
	allDoSamePut(t, backends, "foo", testString, false)

	// Get should see that entry.
	allDoSameGet(t, backends, "foo", &logical.StorageEntry{Key: "foo", Value: testString}, false)

	// Make a nested entry.
	bazString := []byte("baz")
	allDoSamePut(t, backends, "foo/bar", bazString, false)

	// Get should work on it.
	allDoSameGet(t, backends, "foo/bar", &logical.StorageEntry{Key: "foo/bar", Value: bazString}, false)

	// List should have both a key and a subtree.
	allDoSameList(t, backends, "", []string{"foo", "foo/"}, false)
	allDoSameListPage(t, backends, "", "", -1, []string{"foo", "foo/"}, false)
	allDoSameListPage(t, backends, "", "asdf", -1, []string{"foo", "foo/"}, false)
	allDoSameListPage(t, backends, "", "asdf", 11, []string{"foo", "foo/"}, false)

	// Delete with children should only remove the base entry.
	allDoSameDelete(t, backends, "foo", false)
	allDoSameList(t, backends, "", []string{"foo/"}, false)
	allDoSameListPage(t, backends, "", "", -1, []string{"foo/"}, false)

	// Get should not fail, but be nil.
	allDoSameGet(t, backends, "foo", nil, false)

	// Get should return the child still.
	allDoSameGet(t, backends, "foo/bar", &logical.StorageEntry{Key: "foo/bar", Value: bazString}, false)

	// Removal of random nested secrets should not leave artifacts.
	allDoSamePut(t, backends, "foo/nested1/nested2/nested3/nested4", bazString, false)
	allDoSameDelete(t, backends, "foo/nested1/nested2/nested3/nested4", false)
	allDoSameList(t, backends, "foo/", []string{"bar"}, false)
	allDoSameListPage(t, backends, "foo/", "", -1, []string{"bar"}, false)

	// Make a second entry to test prefix removal.
	zapString := []byte("zap")
	allDoSamePut(t, backends, "foo/zip", zapString, false)

	// Delete should not remove the prefix.
	allDoSameDelete(t, backends, "foo/bar", false)
	allDoSameList(t, backends, "", []string{"foo/"}, false)
	allDoSameListPage(t, backends, "", "", -1, []string{"foo/"}, false)

	// Zip's contents should not be affected by this delete.
	allDoSameGet(t, backends, "foo/zip", &logical.StorageEntry{Key: "foo/zip", Value: zapString}, false)

	// Repeated writes to zip should yield the last one. Note that the final
	// write is shorter than an intermediate write.
	allDoSamePut(t, backends, "foo/zip", zapString, false)
	allDoSamePut(t, backends, "foo/zip", testString, false)
	allDoSamePut(t, backends, "foo/zip", bazString, false)
	allDoSameGet(t, backends, "foo/zip", &logical.StorageEntry{Key: "foo/zip", Value: bazString}, false)

	// Delete zip, getting back the empty storage.
	allDoSameDelete(t, backends, "foo/zip", false)
	allDoSameList(t, backends, "", nil, false)
	allDoSameListPage(t, backends, "", "", -1, nil, false)
	allDoSameListPage(t, backends, "", "asdf", -1, nil, false)
	allDoSameListPage(t, backends, "", "asdf", 11, nil, false)

	// Creating a deeply nested entry in an empty root should show up on
	// list.
	allDoSamePut(t, backends, "foo/nested1/nested2/nested3/nested4", bazString, false)
	allDoSameList(t, backends, "", []string{"foo/"}, false)
	allDoSameListPage(t, backends, "", "", -1, []string{"foo/"}, false)

	// Deleting it should leave no artifacts.
	allDoSameDelete(t, backends, "foo/nested1/nested2/nested3/nested4", false)
	allDoSameList(t, backends, "", nil, false)
	allDoSameListPage(t, backends, "", "", -1, nil, false)

	// Finally, test pagination exhaustively.
	var created []string
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("key-%d", i)
		allDoSamePut(t, backends, name, testString, false)
		created = append(created, name)

		// Listing everything should work.
		allDoSameList(t, backends, "", created, false)
		allDoSameListPage(t, backends, "", "", -1, created, false)

		// Listing after our previous entry should work.
		justBefore := ""
		if len(created) >= 2 {
			justBefore = created[len(created)-2]
		}
		allDoSameListPage(t, backends, "", justBefore, -1, []string{name}, false)
		allDoSameListPage(t, backends, "", justBefore, 1, []string{name}, false)
		allDoSameListPage(t, backends, "", justBefore, 2, []string{name}, false)

		// Listing previously created entries should work. Note that limit=0
		// is equivalent to limit=-1 and thus returns all entries.
		if i > 0 {
			allDoSameListPage(t, backends, "", "", i, created[:i], false)
			allDoSameListPage(t, backends, "", "asdf", i, created[:i], false)
			allDoSameListPage(t, backends, "", "key-", i, created[:i], false)
			allDoSameListPage(t, backends, "", "aaaaaaaaaaaaaaaa", i, created[:i], false)
		}

		// Listing future entries should be blank.
		allDoSameListPage(t, backends, "", name, -1, nil, false)
		allDoSameListPage(t, backends, "", "key-99999999", -1, nil, false)
		allDoSameListPage(t, backends, "", "zzzzzzzzz", -1, nil, false)
	}

	// Finally, clean up after paginated list testing.
	for _, name := range created {
		allDoSameDelete(t, backends, name, false)
	}
}

func exerciseTransactions(t *testing.T, backends map[string]logical.TransactionalStorage) {
	direct := make(map[string]logical.Storage, len(backends))
	for name, backend := range backends {
		direct[name] = backend.(logical.Storage)
	}

	// Creating a transaction and committing or rolling it back without doing
	// anything should succeed, regardless of type of transaction. Doing the
	// same operation twice should fail as the transaction was already
	// finished.
	txns := allDoSameBeginTx(t, backends, false)
	allDoSameCommit(t, txns, false)
	allDoSameCommit(t, txns, true)
	txns = allDoSameBeginReadOnlyTx(t, backends, false)
	allDoSameCommit(t, txns, false)
	allDoSameCommit(t, txns, true)
	txns = allDoSameBeginTx(t, backends, false)
	allDoSameRollback(t, txns, false)
	allDoSameRollback(t, txns, true)
	txns = allDoSameBeginReadOnlyTx(t, backends, false)
	allDoSameRollback(t, txns, false)
	allDoSameRollback(t, txns, true)

	// This should also be true if we swap types (commit->rollback and
	// visa-versa).
	txns = allDoSameBeginTx(t, backends, false)
	allDoSameCommit(t, txns, false)
	allDoSameRollback(t, txns, true)
	txns = allDoSameBeginReadOnlyTx(t, backends, false)
	allDoSameCommit(t, txns, false)
	allDoSameRollback(t, txns, true)
	txns = allDoSameBeginTx(t, backends, false)
	allDoSameRollback(t, txns, false)
	allDoSameCommit(t, txns, true)
	txns = allDoSameBeginReadOnlyTx(t, backends, false)
	allDoSameRollback(t, txns, false)
	allDoSameCommit(t, txns, true)

	// Empty transactions can be interwoven.
	txn1 := allDoSameBeginTx(t, backends, false)
	txn2 := allDoSameBeginTx(t, backends, false)
	allDoSameCommit(t, txn2, false)
	allDoSameCommit(t, txn1, false)

	// Writing to a read-only transaction should fail; committing this
	// transaction should have no impact on storage.
	test := []byte("test")
	rtx := allDoSameBeginReadOnlyTx(t, backends, false)
	allDoSamePut(t, rtx, "foo", test, true)
	allDoSameDelete(t, rtx, "foo", true)
	allDoSameCommit(t, rtx, false)
	allDoSameList(t, direct, "", nil, false)

	// Creating the same entry in two transactions should conflict the
	// second committed one, even though they have the same contents.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSamePut(t, txn1, "foo", test, false)
	allDoSamePut(t, txn2, "foo", test, false)
	allDoSameCommit(t, txn1, false)
	allDoSameCommit(t, txn2, true)
	allDoSameGet(t, direct, "foo", &logical.StorageEntry{Key: "foo", Value: test}, false)

	baz := []byte("baz")
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSamePut(t, txn1, "foo", baz, false)
	allDoSamePut(t, txn2, "foo", baz, false)
	allDoSameCommit(t, txn2, false)
	allDoSameCommit(t, txn1, true)
	allDoSameGet(t, direct, "foo", &logical.StorageEntry{Key: "foo", Value: baz}, false)

	// Creating different entries in two transactions should be fine.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSamePut(t, txn1, "foo", test, false)
	allDoSamePut(t, txn2, "bar", baz, false)
	allDoSameCommit(t, txn1, false)
	allDoSameCommit(t, txn2, false)
	allDoSameGet(t, direct, "foo", &logical.StorageEntry{Key: "foo", Value: test}, false)
	allDoSameGet(t, direct, "bar", &logical.StorageEntry{Key: "bar", Value: baz}, false)

	// Getting an item and writing to the same item in different transactions
	// should fail one of the two.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSameGet(t, txn1, "bar", &logical.StorageEntry{Key: "bar", Value: baz}, false)
	allDoSamePut(t, txn1, "foo", baz, false)
	allDoSameGet(t, txn2, "foo", &logical.StorageEntry{Key: "foo", Value: test}, false)
	allDoSamePut(t, txn2, "bar", test, false)
	allDoSameCommit(t, txn1, false)
	allDoSameCommit(t, txn2, true)
	allDoSameGet(t, direct, "foo", &logical.StorageEntry{Key: "foo", Value: baz}, false)
	allDoSameGet(t, direct, "bar", &logical.StorageEntry{Key: "bar", Value: baz}, false)

	// Try again, with delete this time, committing in a different order.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSameGet(t, txn1, "bar", &logical.StorageEntry{Key: "bar", Value: baz}, false)
	allDoSameDelete(t, txn1, "foo", false)
	allDoSameGet(t, txn2, "foo", &logical.StorageEntry{Key: "foo", Value: baz}, false)
	allDoSameDelete(t, txn2, "bar", false)
	allDoSameCommit(t, txn2, false)
	allDoSameCommit(t, txn1, true)
	allDoSameGet(t, direct, "foo", &logical.StorageEntry{Key: "foo", Value: baz}, false)
	allDoSameList(t, direct, "", []string{"foo"}, false)

	// Reading entries that don't exist shouldn't cause issues.
	txns = allDoSameBeginTx(t, backends, false)
	allDoSameGet(t, txns, "bar", nil, false)
	allDoSameGet(t, txns, "foo", &logical.StorageEntry{Key: "foo", Value: baz}, false)
	allDoSameDelete(t, txns, "foo", false)
	allDoSameCommit(t, txns, false)
	allDoSameList(t, direct, "", nil, false)
}

func getRandomOps(t *testing.T, count int, transactional bool, txLimit int) []*inmem.InmemOp {
	var ops []*inmem.InmemOp

	// Track transactions. Allow
	opTypes := []int{
		inmem.PutInMemOp, inmem.DeleteInMemOp,
		inmem.ListInMemOp, inmem.ListPageInMemOp,
		inmem.GetInMemOp,
	}
	if transactional {
		opTypes = append(opTypes, []int{
			inmem.BeginTxInMemOp, inmem.BeginReadOnlyTxInMemOp,
			inmem.CommitTxInMemOp, inmem.RollbackTxInMemOp,
		}...)
	}

	// We only want to create files, but will allow delete/get/list on
	// both files and folders.
	opFiles := []string{
		"a",
		"b",
		"c",
		"d",
		"e",
		"f",
		"foo",
		"foo/apple",
		"foo/bar",
		"foo/baz",
		"foo/cherry",
		"foo/foo",
		"foo/fud",
		"foo/very/highly/nested/subpath",
		"foo/very/highly/nested/subpath/that/goes/on/for/ever/and/ever/and/ever/until/it/runs/out/of/usual/path/space/on/a/file/system",
		"g",
		"h",
		"i",
		"z",
	}

	opFolders := []string{
		"",
		"foo/very",
		"foo/very/highly",
		"foo/very/highly/nested",
		"foo/very/highly/nested/subpath/that",
		"foo/very/highly/nested/subpath/that/goes/on/for/ever/and/ever/and/ever/until/it/runs/out/of/usual/path/space/on/a/file",
		"this-path-does-not-exist",
		"this/path/also/does/not/exist",
	}
	opFolders = append(opFolders, opFiles...)

	var opAfter []string
	for _, entry := range opFolders {
		opAfter = append(opAfter, filepath.Base(entry))
	}

	opContents := []string{
		"",
		"here",
		"a",
		"test",
		"there",
		"is-a-test",
		"everywhere-is",
		"a-test",
		"bar",
		"baz",
		"somewhat-long-string-with-very",
		"always-last-add-new-ones-above-me-start-of-a-very-very-long-string-",
	}
	for len(opContents[len(opContents)-1]) < 32*1024 {
		opContents[len(opContents)-1] += "0123456789"
	}

	for i := 0; i < count; i++ {
		opI := rand.Intn(len(opTypes))
		op := opTypes[opI]

		var tx int = rand.Intn(txLimit+1) - 1
		var path string
		var contents string
		var after string
		var limit int
		switch op {
		case inmem.PutInMemOp:
			pathI := rand.Intn(len(opFiles))
			path = opFiles[pathI]
			contentsI := rand.Intn(len(opContents))
			contents = opContents[contentsI]
		case inmem.DeleteInMemOp, inmem.GetInMemOp, inmem.ListInMemOp:
			pathI := rand.Intn(len(opFolders))
			path = opFolders[pathI]
		case inmem.ListPageInMemOp:
			pathI := rand.Intn(len(opFolders))
			path = opFolders[pathI]
			afterI := rand.Intn(len(opAfter))
			after = opAfter[afterI]
		case inmem.CommitTxInMemOp, inmem.RollbackTxInMemOp, inmem.BeginTxInMemOp, inmem.BeginReadOnlyTxInMemOp:
			tx = rand.Intn(txLimit)
		default:
			t.Fatalf("unknown op: %v", op)
		}

		if (op == inmem.ListInMemOp || op == inmem.ListPageInMemOp) && path != "" {
			path = path + "/"
		}

		ops = append(ops, &inmem.InmemOp{
			OpType:   op,
			OpTx:     tx,
			ArgKey:   path,
			ArgAfter: after,
			ArgLimit: limit,
			ArgEntry: &physical.Entry{
				Key:   path,
				Value: []byte(contents),
			},
		})
	}

	return ops
}

func executeRandomOps(t *testing.T, backends map[string]logical.Storage, ops []*inmem.InmemOp) {
	data, err := json.Marshal(ops)
	require.NoError(t, err, "failed to marshal ops to json")
	err = os.WriteFile(opsLogFile, data, 0o644)
	require.NoError(t, err, "failed to save ops to file")

	for index, op := range ops {
		switch op.OpType {
		case inmem.PutInMemOp:
			allDoSamePut(t, backends, op.ArgEntry.Key, op.ArgEntry.Value, false)
		case inmem.DeleteInMemOp:
			allDoSameDelete(t, backends, op.ArgKey, false)
		case inmem.GetInMemOp:
			allDoSameGetNoBenchmark(t, backends, op.ArgKey, false)
		case inmem.ListInMemOp:
			allDoSameListNoBenchmark(t, backends, op.ArgKey, false)
		case inmem.ListPageInMemOp:
			allDoSameListPageNoBenchmark(t, backends, op.ArgKey, op.ArgAfter, op.ArgLimit, false)
		default:
			t.Fatalf("[%d] unknown operation: %v (%v)", index, op.OpType, inmem.OpName(op.OpType))
		}
	}

	os.Remove(opsLogFile)
}

func executeRandomTransactionalOps(t *testing.T, txBackends map[string]logical.TransactionalStorage, ops []*inmem.InmemOp, txLimit int) {
	data, err := json.Marshal(ops)
	require.NoError(t, err, "failed to marshal ops to json")
	err = os.WriteFile(txOpsLogFile, data, 0o644)
	require.NoError(t, err, "failed to save ops to file")

	direct := make(map[string]logical.Storage, len(txBackends))
	for name, backend := range txBackends {
		direct[name] = backend.(logical.Storage)
	}

	txs := make([]map[string]logical.Storage, txLimit)
	for index, op := range ops {
		var listRet map[string][]string
		var entryRet map[string]*logical.StorageEntry
		var errorRet map[string]error

		bk := direct
		if op.OpTx >= 0 && op.OpTx < txLimit {
			bk = txs[op.OpTx]
		}
		if bk == nil {
			continue
		}

		switch op.OpType {
		case inmem.PutInMemOp:
			errorRet = allDoPut(t, bk, op.ArgEntry.Key, op.ArgEntry.Value)
		case inmem.DeleteInMemOp:
			errorRet = allDoDelete(t, bk, op.ArgKey)
		case inmem.GetInMemOp:
			entryRet, errorRet = allDoGet(t, bk, op.ArgKey)
		case inmem.ListInMemOp:
			listRet, errorRet = allDoList(t, bk, op.ArgKey)
		case inmem.ListPageInMemOp:
			listRet, errorRet = allDoListPage(t, bk, op.ArgKey, op.ArgAfter, op.ArgLimit)
		case inmem.BeginTxInMemOp:
			if txs[op.OpTx] != nil {
				allDoSameRollback(t, txs[op.OpTx], false)
				txs[op.OpTx] = nil
			}

			txs[op.OpTx], errorRet = allDoBeginTx(t, txBackends)
		case inmem.BeginReadOnlyTxInMemOp:
			if txs[op.OpTx] != nil {
				allDoSameRollback(t, txs[op.OpTx], false)
				txs[op.OpTx] = nil
			}

			txs[op.OpTx], errorRet = allDoBeginReadOnlyTx(t, txBackends)
		case inmem.CommitTxInMemOp:
			errorRet = allDoCommit(t, bk)
			txs[op.OpTx] = nil
		case inmem.RollbackTxInMemOp:
			errorRet = allDoRollback(t, bk)
			txs[op.OpTx] = nil
		default:
			t.Fatalf("unknown operation: %v (%v)", op.OpType, inmem.OpName(op.OpType))
		}

		var errExpected error
		var errExpectedName string
		for name, err := range errorRet {
			if errExpectedName == "" {
				errExpectedName = name
				errExpected = err
				continue
			}

			if (errExpected != nil) != (err != nil) {
				t.Fatalf("[op %d] different error results for %v (%v):\n==== %v ====\n\t%v\n==== %v ====\n\t%v\n", index, op.OpType, inmem.OpName(op.OpType), errExpectedName, errExpected, name, err)
			}
		}

		if listRet != nil {
			var listExpected []string
			var listExpectedName string
			for name, result := range listRet {
				if listExpectedName == "" {
					listExpectedName = name
					listExpected = result
					continue
				}

				if len(listExpected) == 0 && len(result) == 0 {
					continue
				}

				if diff := deep.Equal(listExpected, result); diff != nil {
					t.Fatalf("[op %d] different list results for %v (%v):\n==== %v ====\n\t%v\n==== %v ====\n\t%v\n==== diff ====\n%v\n", index, op.OpType, inmem.OpName(op.OpType), listExpectedName, listExpected, name, err, diff)
				}
			}
		}

		if entryRet != nil {
			var entryExpected *logical.StorageEntry
			var entryExpectedName string
			for name, result := range entryRet {
				if entryExpectedName == "" {
					entryExpectedName = name
					entryExpected = result
					continue
				}

				if diff := deep.Equal(entryExpected, result); diff != nil {
					t.Fatalf("[op %d] different entry results for %v (%v):\n==== %v ====\n\t%v\n==== %v ====\n\t%v\n==== diff ====\n%v\n", index, op.OpType, inmem.OpName(op.OpType), entryExpectedName, entryExpected, name, err, diff)
				}
			}
		}

	}

	os.Remove(txOpsLogFile)
}
