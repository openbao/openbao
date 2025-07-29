package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/openbao/openbao/sdk/v2/physical"
)

type InvalidationStrategy string

const (
	WALTableInvalidationStrategy InvalidationStrategy = "wal_table"
)

func (p *PostgreSQLBackend) LeadershipChange(active bool) {
	p.active.Store(active)
}

func (p *PostgreSQLBackend) HookInvalidate(hook physical.InvalidateFunc) {
	p.invalidateLock.Lock()
	defer p.invalidateLock.Unlock()

	if p.invalidateDoneCh != nil {
		p.invalidateDoneCh <- struct{}{}
		close(p.invalidateDoneCh)
	}

	p.invalidate = hook
	p.consumedInvalidations = make(map[int64]struct{})

	if hook != nil {
		p.logger.Trace("starting invalidation processing...")
		p.invalidateDoneCh = make(chan struct{})
		go p.ProcessInvalidations(p.invalidateDoneCh)
	}
}

func (p *PostgreSQLBackend) ProcessInvalidations(closeCh chan struct{}) {
	lastWasActive := p.active.Load()

	for {
		select {
		case <-closeCh:
			p.logger.Trace("quitting invalidation processing...")
			return
		default:
		}

		active := p.active.Load()

		var err error
		switch p.invalidationStrategy {
		case WALTableInvalidationStrategy:
			err = p.doAllTableInvalidation(closeCh, lastWasActive, active)
		}

		if err != nil {
			p.logger.Error("invalidation process failed", "error", err)
		}

		lastWasActive = active

		// Provide for backoff; some strategies may be long-running, others
		// might be expecting us to loop for them.
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *PostgreSQLBackend) writeInvalidation(ctx context.Context, txn *sql.Tx, key string) error {
	if !p.active.Load() {
		return nil
	}

	switch p.invalidationStrategy {
	case WALTableInvalidationStrategy:
		_, err := txn.ExecContext(ctx, p.tableWalInvalidateQuery, key)
		if err != nil {
			return fmt.Errorf("failed to write invalidation: %w", err)
		}
	default:
		return fmt.Errorf("unknown invalidation strategy: %v", p.invalidationStrategy)
	}

	return nil
}

func (p *PostgreSQLBackend) doAllTableInvalidation(closeCh chan struct{}, lastWasActive bool, nowActive bool) error {
	switch nowActive {
	case true:
		// Prune the table.
		return p.pruneInvalidationTable(closeCh, lastWasActive)
	case false:
		// Check for invalidations
		return p.consumeInvalidationTable(closeCh)
	}

	return nil
}

func (p *PostgreSQLBackend) pruneInvalidationTable(closeCh chan struct{}, lastWasActive bool) error {
	// XXX - we need to know if there's any entries in the able which can be deleted because all registered clients have consumed them.
	if lastWasActive {
		// Nothing to do right now.
		return nil
	}

	p.logger.Trace("clearing WAL table now that active")

	// Truncate the WAL entirely; leadership changed.
	checkpoint, err := p.GetCurrentHACheckpoint(context.Background())
	if err != nil {
		return err
	}

	p.invalidateLock.Lock()
	p.lastSeenWal = checkpoint
	p.logger.Trace("last seen WAL prior to invalidation", "index", p.lastSeenWal)
	p.invalidateLock.Unlock()

	if _, err := p.client.Exec("DELETE FROM " + p.walTable); err != nil {
		return err
	}

	return nil
}

func (p *PostgreSQLBackend) GetHACheckpoint(ctx context.Context) (string, error) {
	p.invalidateLock.RLock()
	defer p.invalidateLock.RUnlock()

	return p.lastSeenWal, nil
}

func (p *PostgreSQLBackend) GetCurrentHACheckpoint(ctx context.Context) (string, error) {
	var checkpoint string

	row := p.client.QueryRowContext(ctx, "SELECT pg_current_wal_lsn::text FROM pg_current_wal_lsn()")
	if row.Err() != nil {
		return "", row.Err()
	}

	if err := row.Scan(&checkpoint); err != nil {
		return "", err
	}

	return checkpoint, nil
}

func (p *PostgreSQLBackend) WaitHACheckpoint(ctx context.Context, checkpoint string) error {
	var b backoff.BackOff = backoff.NewExponentialBackOff(
		backoff.WithMaxInterval(1*time.Second),
		backoff.WithInitialInterval(15*time.Millisecond),
	)

	b.Reset()

	if err := backoff.Retry(func() error {
		row := p.client.QueryRowContext(ctx, "SELECT pg_current_wal_lsn - '$1'::pg_lsn FROM pg_current_wal_lsn()", checkpoint)
		if row.Err() != nil {
			return fmt.Errorf("error querying current wal value: %w", row.Err())
		}

		var value int64
		if err := row.Scan(&value); err != nil {
			return fmt.Errorf("failed to scan current wal value: %w", err)
		}

		if value < 0 {
			return fmt.Errorf("waiting for wal to catch up: remaining=%v", -1*value)
		}

		if ctx.Err() != nil {
			return backoff.Permanent(ctx.Err())
		}

		return nil
	}, b); err != nil {
		return fmt.Errorf("checkpoint wait failed: %w", err)
	}

	return nil
}

func (p *PostgreSQLBackend) consumeInvalidationTable(closeCh chan struct{}) error {
	// There is no filtering we can do here that will help reduce the size of
	// this table. In the event a client remains out of date, the leader
	// should prune that node and force them to catch up via the checkpoint
	// wait system. In particular, the following methods do not work:
	//
	// 1. WAL value: this is the value when stashing the write not when the
	//    transaction commits the WAL write to disk. Thus we could see the
	//    (higher) WAL value B before we see A and if we use it to filter,
	//    would miss A altogether.
	// 2. Date/time: same as above; Now() evaluates at the time the statement
	//    is sent and not the time of commit.
	// 3. SERIAL or equivalent: this is not guaranteed to be monotonically
	//    increasing and values may be skipped and/or before already seen
	//    values.
	//
	// We thus load every value from the table, send invalidations, and
	// discard any entries from our seen table that no longer exist in the
	// WAL table.
	rows, err := p.client.Query("SELECT idx, path FROM " + p.walTable)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}

	defer rows.Close()

	seenEntries := make(map[int64]struct{})
	for rows.Next() {
		select {
		case <-closeCh:
			return fmt.Errorf("invalidation cancelled")
		default:
		}

		var index int64
		var key string
		if err := rows.Scan(&index, &key); err != nil {
			return err
		}

		p.invalidateLock.RLock()
		_, seen := p.consumedInvalidations[index]
		if !seen && p.invalidate != nil {
			p.logger.Trace("invalidating key...", "key", key)
			p.invalidate(key)
		}
		p.invalidateLock.RUnlock()

		seenEntries[index] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}

	p.invalidateLock.Lock()
	p.consumedInvalidations = seenEntries
	p.invalidateLock.Unlock()

	return nil
}
