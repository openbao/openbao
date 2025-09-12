// We wish to build a backend cross-testing framework which allows us to find
// differences in the way various storage interfaces behave. This will also
// ultimately allow us to compose and stack various layers to ensure we have
// correct semantics across composition as well.
//
// In OpenBao, the following storage layers are used, from lowest to highest:
//
//	[disk]
//	1. A low-level backend, such as raft, file, or inmem. Only the former is
//	   supported for production use, but inmem is frequently used for dev mode
//	   and as a part of our test suite.
//	2. A cache; this caches read operations, avoiding having to round-trip to
//	   a potentially slow backend over a slow network for repeated reads to
//	   the same entry.
//	3. An error validation layer (encoding); this prevents writes with invalid
//	   keys (non-utf-8 or non-printable characters).
//	4. Our barrier encryption; this handles all encryption of storage entries.
//	   At this point, we convert a physical.Backend into a logical.Storage
//	   interface.
//	5. A storage view; this restricts the access of the above barrier
//	   encryption layer to a prefix.
//	6. A barrier view; this is what is ultimately given to the backends; it
//	   has a limited interface.
//	[plugin]
//
// In the event of a GRPC-attached plugin, another layer appears as the GRPC
// client stubs out support to transit storage operations through to the
// GRPC server, though this isn't tested here.
package crosstest

import (
	"context"
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
)

const (
	opsLogFile   = "/tmp/openbao-physical-random-ops.json"
	txOpsLogFile = "/tmp/openbao-physical-random-tx-ops.json"
	numOps       = 1000
	numTxOps     = numOps
)

func Test_ExerciseBackends(t *testing.T) {
	t.Parallel()

	backends, cleanup := allPhysical(t)
	defer cleanup()

	exerciseBackends(t, backends)

	// If any were transactions, let's rollback. We can't commit them as
	// we wrote to the same area of storage in lots of places.
	for name, backend := range backends {
		if txn, ok := backend.(physical.Transaction); ok {
			err := txn.Rollback(context.Background())
			require.NoError(t, err, "failed to rollback transaction: %v", name)
		}
	}
}

func Test_RandomOpsBackends(t *testing.T) {
	t.Parallel()

	backends, cleanup := allPhysical(t)
	defer cleanup()

	ops := getRandomOps(t, numOps, false, 0)
	// ops := replayOps(t, opsLogFile)
	executeRandomOps(t, backends, ops)
}

func Test_RandomOpsTransactionalBackends(t *testing.T) {
	t.Parallel()

	backends, cleanup := allTransactionalPhysical(t)
	defer cleanup()

	txLimit := 10
	ops := getRandomOps(t, numTxOps, true, txLimit)
	executeRandomTransactionalOps(t, backends, ops, txLimit)
}

func Test_ExerciseTransactionalBackends(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	backends, cleanup := allTransactionalPhysical(t)
	defer cleanup()

	// Create transactions and exercise the backend, rolling them back.
	txns := make(map[string]physical.Backend, 2*len(backends))
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
		err := txn.(physical.Transaction).Rollback(ctx)
		require.NoError(t, err, "failed to rollback transaction: %v", name)
	}

	// Ensure we can do a single read/write transactions and commit them.
	// This will leave us with an empty state, but potentially entries in
	// any transaction logs.
	txns = make(map[string]physical.Backend, len(backends))
	for name, backend := range backends {
		txn, err := backend.BeginTx(ctx)
		require.NoError(t, err, "failed to create write transaction: %v", name)
		txns[fmt.Sprintf("%v-tx-rw", name)] = txn
	}

	exerciseBackends(t, txns)

	for name, txn := range txns {
		err := txn.(physical.Transaction).Commit(ctx)
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

func allPhysical(t *testing.T) (map[string]physical.Backend, func()) {
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

	// txinmem-in-tx
	txinmtx, err := txinm.BeginTx(ctx)
	require.NoError(t, err, "failed to start transaction from transactional in-memory backend")

	// postgresql
	psql, psqlCleanup := postgresql.GetTestPostgreSQLBackend(t, logger)

	// Now compose multiple storage backends together!

	// raft + cache
	rbc, raftCacheDir := raft.GetRaft(t, true, true)
	crb := physical.NewCache(rbc, 0, logger, &metrics.BlackholeSink{})

	// raft + cache-in-tx
	rbctx := physical.NewCache(rbc, 0, logger, &metrics.BlackholeSink{})
	ctxr, err := rbctx.(physical.TransactionalBackend).BeginTx(ctx)
	require.NoError(t, err, "failed to start cache transaction from raft backend")

	// raft-in-tx + cache
	rtc, err := rbc.BeginTx(ctx)
	require.NoError(t, err, "failed to start raft transaction for cache")
	crt := physical.NewCache(rtc, 0, logger, &metrics.BlackholeSink{})

	// file + cache
	fbc, fileCacheCleanup := getFile(t, logger)
	cfb := physical.NewCache(fbc, 0, logger, &metrics.BlackholeSink{})

	// inmem + cache
	inmc, err := inmem.NewInmem(disableTxConf, logger)
	require.NoError(t, err, "failed to create in-memory backend for cache")
	cinm := physical.NewCache(inmc, 0, logger, &metrics.BlackholeSink{})

	// psql + cache
	psqlc, psqlcCleanup := postgresql.GetTestPostgreSQLBackend(t, logger)
	cpsql := physical.NewCache(psqlc, 0, logger, &metrics.BlackholeSink{})

	// raft + encoding
	rbe, raftEncodingDir := raft.GetRaft(t, true, true)
	erb := physical.NewStorageEncoding(rbe)

	// raft + encoding-in-tx
	rbetx := physical.NewStorageEncoding(rbe)
	etxr, err := rbetx.(physical.TransactionalBackend).BeginTx(ctx)
	require.NoError(t, err, "failed to start encoding transaction from raft backend")

	// raft-in-tx + encoding
	rte, err := rbe.BeginTx(ctx)
	require.NoError(t, err, "failed to start raft transaction for encoding")
	ert := physical.NewStorageEncoding(rte)

	// file + encoding
	fbe, fileEncodingCleanup := getFile(t, logger)
	efb := physical.NewStorageEncoding(fbe)

	// inmem + encoding
	inme, err := inmem.NewInmem(disableTxConf, logger)
	require.NoError(t, err, "failed to create in-memory backend for encoding")
	einm := physical.NewStorageEncoding(inme)

	// psql + encoding
	psqle, psqleCleanup := postgresql.GetTestPostgreSQLBackend(t, logger)
	epsql := physical.NewStorageEncoding(psqle)

	// raft + cache + encoding
	rbce, raftCacheEncodingDir := raft.GetRaft(t, true, true)
	crbe := physical.NewCache(rbce, 0, logger, &metrics.BlackholeSink{})
	erbc := physical.NewStorageEncoding(crbe)

	// file + cache + encoding
	fbce, fileCacheEncodingCleanup := getFile(t, logger)
	cfbe := physical.NewCache(fbce, 0, logger, &metrics.BlackholeSink{})
	efbc := physical.NewStorageEncoding(cfbe)

	// inmem + cache + encoding
	inmce, err := inmem.NewInmem(disableTxConf, logger)
	require.NoError(t, err, "failed to create in-memory backend for cache+encoding")
	cinme := physical.NewCache(inmce, 0, logger, &metrics.BlackholeSink{})
	einmc := physical.NewStorageEncoding(cinme)

	// psql + encoding
	psqlce, psqlceCleanup := postgresql.GetTestPostgreSQLBackend(t, logger)
	cpsqle := physical.NewCache(psqlce, 0, logger, &metrics.BlackholeSink{})
	epsqlc := physical.NewStorageEncoding(cpsqle)

	return map[string]physical.Backend{
			"pure-raft": prb,

			"raft":                rb,
			"raft+cache":          crb,
			"raft+encoding":       erb,
			"raft+cache+encoding": erbc,

			"raft-in-tx":          rt,
			"raft-in-tx+cache":    crt,
			"raft-in-tx+encoding": ert,

			"raft+cache-in-tx":    ctxr,
			"raft+encoding-in-tx": etxr,

			"file":                fb,
			"file+cache":          cfb,
			"file+encoding":       efb,
			"file+cache+encoding": efbc,

			"inmem":                inm,
			"inmem+cache":          cinm,
			"inmem+encoding":       einm,
			"inmem+cache+encoding": einmc,

			"txinmem": txinm,

			"txinmtx": txinmtx,

			"psql":                psql,
			"psql+cache":          cpsql,
			"psql+encoding":       epsql,
			"psql+cache+encoding": epsqlc,
		}, func() {
			os.RemoveAll(raftPureDir)
			os.RemoveAll(raftDir)
			fileCleanup()
			psqlCleanup()
			os.RemoveAll(raftCacheDir)
			fileCacheCleanup()
			psqlcCleanup()
			os.RemoveAll(raftEncodingDir)
			fileEncodingCleanup()
			psqleCleanup()
			os.RemoveAll(raftCacheEncodingDir)
			fileCacheEncodingCleanup()
			psqlceCleanup()
		}
}

func allTransactionalPhysical(t *testing.T) (map[string]physical.TransactionalBackend, func()) {
	logger := logging.NewVaultLogger(log.Debug)

	// Basic storage backends.

	// raft
	rb, raftDir := raft.GetRaft(t, true, true)

	// raft + cache
	rbc, raftCacheDir := raft.GetRaft(t, true, true)
	crb := physical.NewCache(rbc, 0, logger, &metrics.BlackholeSink{}).(physical.TransactionalBackend)

	// raft + encoding
	rbe, raftEncodingDir := raft.GetRaft(t, true, true)
	erb := physical.NewStorageEncoding(rbe).(physical.TransactionalBackend)

	// raft + cache + encoding
	rbce, raftCacheEncodingDir := raft.GetRaft(t, true, true)
	crbe := physical.NewCache(rbce, 0, logger, &metrics.BlackholeSink{}).(physical.TransactionalBackend)
	ecrb := physical.NewStorageEncoding(crbe).(physical.TransactionalBackend)

	// inmem
	_im, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem")
	im := _im.(physical.TransactionalBackend)

	// inmem + cache
	_imc, err := inmem.NewInmem(nil, logger)
	require.NoError(t, err, "failed to create transactional in-mem for cache")
	imc := _imc.(physical.TransactionalBackend)
	cim := physical.NewCache(imc, 0, logger, &metrics.BlackholeSink{}).(physical.TransactionalBackend)

	return map[string]physical.TransactionalBackend{
			"raft":                rb,
			"raft+cache":          crb,
			"raft+encoding":       erb,
			"raft+cache+encoding": ecrb,
			"txinmem":             im,
			"txinmem+cache":       cim,
		}, func() {
			os.RemoveAll(raftDir)
			os.RemoveAll(raftCacheDir)
			os.RemoveAll(raftEncodingDir)
			os.RemoveAll(raftCacheEncodingDir)
		}
}

func allDoList(t *testing.T, backends map[string]physical.Backend, prefix string) (map[string][]string, map[string]error) {
	results := make(map[string][]string, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.List(context.Background(), prefix)
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoListPage(t *testing.T, backends map[string]physical.Backend, prefix string, after string, limit int) (map[string][]string, map[string]error) {
	results := make(map[string][]string, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.ListPage(context.Background(), prefix, after, limit)
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoDelete(t *testing.T, backends map[string]physical.Backend, key string) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		err := backend.Delete(context.Background(), key)
		errs[name] = err
	}

	return errs
}

func allDoPut(t *testing.T, backends map[string]physical.Backend, key string, value []byte) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		// Other entry fields are unnecessary.
		err := backend.Put(context.Background(), &physical.Entry{
			Key:   key,
			Value: value,
		})
		errs[name] = err
	}

	return errs
}

func allDoGet(t *testing.T, backends map[string]physical.Backend, key string) (map[string]*physical.Entry, map[string]error) {
	results := make(map[string]*physical.Entry, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.Get(context.Background(), key)
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

// Results are physical.Backend to allow for passing to above allDoX methods.
func allDoBeginTx(t *testing.T, backends map[string]physical.TransactionalBackend) (map[string]physical.Backend, map[string]error) {
	results := make(map[string]physical.Backend, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.BeginTx(context.Background())
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoBeginReadOnlyTx(t *testing.T, backends map[string]physical.TransactionalBackend) (map[string]physical.Backend, map[string]error) {
	results := make(map[string]physical.Backend, len(backends))
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		result, err := backend.BeginReadOnlyTx(context.Background())
		results[name] = result
		errs[name] = err
	}

	return results, errs
}

func allDoCommit(t *testing.T, backends map[string]physical.Backend) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		tx := backend.(physical.Transaction)
		err := tx.Commit(context.Background())
		errs[name] = err
	}

	return errs
}

func allDoRollback(t *testing.T, backends map[string]physical.Backend) map[string]error {
	errs := make(map[string]error, len(backends))
	for name, backend := range backends {
		tx := backend.(physical.Transaction)
		err := tx.Rollback(context.Background())
		errs[name] = err
	}

	return errs
}

func allDoSameListNoBenchmark(t *testing.T, backends map[string]physical.Backend, prefix string, shouldError bool) {
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

func allDoSameList(t *testing.T, backends map[string]physical.Backend, prefix string, expected []string, shouldError bool) {
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

func allDoSameListPageNoBenchmark(t *testing.T, backends map[string]physical.Backend, prefix string, after string, limit int, shouldError bool) {
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

func allDoSameListPage(t *testing.T, backends map[string]physical.Backend, prefix string, after string, limit int, expected []string, shouldError bool) {
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

func allDoSameDelete(t *testing.T, backends map[string]physical.Backend, key string, shouldError bool) {
	errs := allDoDelete(t, backends, key)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing DELETE with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing DELETE with backend %v", name)
		}
	}
}

func allDoSameGetNoBenchmark(t *testing.T, backends map[string]physical.Backend, key string, shouldError bool) {
	results, errs := allDoGet(t, backends, key)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing GET with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing GET with backend %v", name)
		}
	}

	var expected *physical.Entry
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

func allDoSameGet(t *testing.T, backends map[string]physical.Backend, key string, expected *physical.Entry, shouldError bool) {
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

func allDoSamePut(t *testing.T, backends map[string]physical.Backend, key string, value []byte, shouldError bool) {
	errs := allDoPut(t, backends, key, value)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing PUT with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing PUT with backend %v", name)
		}
	}
}

func allDoSameBeginTx(t *testing.T, backends map[string]physical.TransactionalBackend, shouldError bool) map[string]physical.Backend {
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

func allDoSameBeginReadOnlyTx(t *testing.T, backends map[string]physical.TransactionalBackend, shouldError bool) map[string]physical.Backend {
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

func allDoSameCommit(t *testing.T, txns map[string]physical.Backend, shouldError bool) {
	errs := allDoCommit(t, txns)
	for name, err := range errs {
		if !shouldError {
			require.NoError(t, err, "error doing Commit with backend %v", name)
		} else {
			require.Error(t, err, "expected error doing Commit with backend %v", name)
		}
	}
}

func allDoSameRollback(t *testing.T, txns map[string]physical.Backend, shouldError bool) {
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
func exerciseBackends(t *testing.T, backends map[string]physical.Backend) {
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
	allDoSameGet(t, backends, "foo", &physical.Entry{Key: "foo", Value: testString}, false)

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
	allDoSameGet(t, backends, "foo", &physical.Entry{Key: "foo", Value: testString}, false)

	// Make a nested entry.
	bazString := []byte("baz")
	allDoSamePut(t, backends, "foo/bar", bazString, false)

	// Get should work on it.
	allDoSameGet(t, backends, "foo/bar", &physical.Entry{Key: "foo/bar", Value: bazString}, false)

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
	allDoSameGet(t, backends, "foo/bar", &physical.Entry{Key: "foo/bar", Value: bazString}, false)

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
	allDoSameGet(t, backends, "foo/zip", &physical.Entry{Key: "foo/zip", Value: zapString}, false)

	// Repeated writes to zip should yield the last one. Note that the final
	// write is shorter than an intermediate write.
	allDoSamePut(t, backends, "foo/zip", zapString, false)
	allDoSamePut(t, backends, "foo/zip", testString, false)
	allDoSamePut(t, backends, "foo/zip", bazString, false)
	allDoSameGet(t, backends, "foo/zip", &physical.Entry{Key: "foo/zip", Value: bazString}, false)

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

func exerciseTransactions(t *testing.T, backends map[string]physical.TransactionalBackend) {
	direct := make(map[string]physical.Backend, len(backends))
	for name, backend := range backends {
		direct[name] = backend
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
	allDoSameGet(t, direct, "foo", &physical.Entry{Key: "foo", Value: test}, false)

	baz := []byte("baz")
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSamePut(t, txn1, "foo", baz, false)
	allDoSamePut(t, txn2, "foo", baz, false)
	allDoSameCommit(t, txn2, false)
	allDoSameCommit(t, txn1, true)
	allDoSameGet(t, direct, "foo", &physical.Entry{Key: "foo", Value: baz}, false)

	// Creating different entries in two transactions should be fine.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSamePut(t, txn1, "foo", test, false)
	allDoSamePut(t, txn2, "bar", baz, false)
	allDoSameCommit(t, txn1, false)
	allDoSameCommit(t, txn2, false)
	allDoSameGet(t, direct, "foo", &physical.Entry{Key: "foo", Value: test}, false)
	allDoSameGet(t, direct, "bar", &physical.Entry{Key: "bar", Value: baz}, false)

	// Getting an item and writing to the same item in different transactions
	// should fail one of the two.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSameGet(t, txn1, "bar", &physical.Entry{Key: "bar", Value: baz}, false)
	allDoSamePut(t, txn1, "foo", baz, false)
	allDoSameGet(t, txn2, "foo", &physical.Entry{Key: "foo", Value: test}, false)
	allDoSamePut(t, txn2, "bar", test, false)
	allDoSameCommit(t, txn1, false)
	allDoSameCommit(t, txn2, true)
	allDoSameGet(t, direct, "foo", &physical.Entry{Key: "foo", Value: baz}, false)
	allDoSameGet(t, direct, "bar", &physical.Entry{Key: "bar", Value: baz}, false)

	// Try again, with delete this time, committing in a different order.
	txn1 = allDoSameBeginTx(t, backends, false)
	txn2 = allDoSameBeginTx(t, backends, false)
	allDoSameGet(t, txn1, "bar", &physical.Entry{Key: "bar", Value: baz}, false)
	allDoSameDelete(t, txn1, "foo", false)
	allDoSameGet(t, txn2, "foo", &physical.Entry{Key: "foo", Value: baz}, false)
	allDoSameDelete(t, txn2, "bar", false)
	allDoSameCommit(t, txn2, false)
	allDoSameCommit(t, txn1, true)
	allDoSameGet(t, direct, "foo", &physical.Entry{Key: "foo", Value: baz}, false)
	allDoSameList(t, direct, "", []string{"foo"}, false)

	// Reading entries that don't exist shouldn't cause issues.
	txns = allDoSameBeginTx(t, backends, false)
	allDoSameGet(t, txns, "bar", nil, false)
	allDoSameGet(t, txns, "foo", &physical.Entry{Key: "foo", Value: baz}, false)
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

func executeRandomOps(t *testing.T, backends map[string]physical.Backend, ops []*inmem.InmemOp) {
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

func executeRandomTransactionalOps(t *testing.T, txBackends map[string]physical.TransactionalBackend, ops []*inmem.InmemOp, txLimit int) {
	data, err := json.Marshal(ops)
	require.NoError(t, err, "failed to marshal ops to json")
	err = os.WriteFile(txOpsLogFile, data, 0o644)
	require.NoError(t, err, "failed to save ops to file")

	direct := make(map[string]physical.Backend, len(txBackends))
	for name, backend := range txBackends {
		direct[name] = backend
	}

	txs := make([]map[string]physical.Backend, txLimit)
	for index, op := range ops {
		var listRet map[string][]string
		var entryRet map[string]*physical.Entry
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
			var entryExpected *physical.Entry
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

func BenchmarkClearView(b *testing.B) {
	prefix := "this-is-a-really-long-path-with-a-uuid-199bae8c-01a4-49a2-8db9-cbddef706b27-plus-some-data-and-another-two-uuids-74ec38e9-b73b-4b7f-9148-809155e8dc91-3a0bc20a-2415-4dfb-a8a3-4d7c8d2bb66d"
	size := 25

	logger := logging.NewVaultLogger(log.Info)

	b.Run("Inmem/WithoutPagination", func(b *testing.B) {
		s := &logical.InmemStorage{}

		randomData(b, s, "secrets-without-pagination/"+prefix, b.N, size)
		count, err := logical.CountKeys(context.Background(), s)
		require.NoError(b, err)
		require.Equal(b, b.N, count)
		b.ResetTimer()

		b.Logf("Starting clear")
		logical.ClearViewWithoutPagination(context.Background(), s, logger)
		b.Logf("Ending clear")

		count, err = logical.CountKeys(context.Background(), s)
		require.NoError(b, err)
		require.Equal(b, 0, count)
	})

	b.Run("Inmem/WithPagination", func(b *testing.B) {
		s := &logical.InmemStorage{}

		randomData(b, s, "secrets-with-pagination/"+prefix, b.N, size)
		count, err := logical.CountKeys(context.Background(), s)
		require.NoError(b, err)
		require.Equal(b, b.N, count)
		b.ResetTimer()

		b.Logf("Starting clear")
		logical.ClearViewWithPagination(context.Background(), s, logger)
		b.Logf("Ending clear")

		count, err = logical.CountKeys(context.Background(), s)
		require.NoError(b, err)
		require.Equal(b, 0, count)
	})

	b.Run("Raft/WithoutPagination", func(b *testing.B) {
		raft, dir := raft.GetRaft(b, true, true)
		defer os.RemoveAll(dir)

		r := logical.NewLogicalStorage(raft)

		randomData(b, r, "secrets-without-pagination/"+prefix, b.N, size)
		count, err := logical.CountKeys(context.Background(), r)
		require.NoError(b, err)
		require.Equal(b, b.N, count)
		b.ResetTimer()

		b.Logf("Starting clear")
		logical.ClearViewWithoutPagination(context.Background(), r, logger)
		b.Logf("Ending clear")

		count, err = logical.CountKeys(context.Background(), r)
		require.NoError(b, err)
		require.Equal(b, 0, count)
	})

	b.Run("Raft/WithPagination", func(b *testing.B) {
		raft, dir := raft.GetRaft(b, true, true)
		defer os.RemoveAll(dir)

		r := logical.NewLogicalStorage(raft)

		randomData(b, r, "secrets-with-pagination/"+prefix, b.N, size)
		count, err := logical.CountKeys(context.Background(), r)
		require.NoError(b, err)
		require.Equal(b, b.N, count)
		b.ResetTimer()

		b.Logf("Starting clear")
		logical.ClearViewWithPagination(context.Background(), r, logger)
		b.Logf("Ending clear")

		count, err = logical.CountKeys(context.Background(), r)
		require.NoError(b, err)
		require.Equal(b, 0, count)
	})
}

func randomData(t testing.TB, s logical.Storage, prefix string, count int, size int) {
	for i := 0; i < count; i++ {
		contents := fmt.Sprintf("%d", i%10)
		for len(contents) < size {
			contents += contents
		}
		contents = contents[0:size]

		entry := fmt.Sprintf("%v-%v", prefix, i)

		if err := s.Put(context.Background(), &logical.StorageEntry{
			Key:   entry,
			Value: []byte(contents),
		}); err != nil {
			t.Fatal(err.Error())
		}
	}
}
