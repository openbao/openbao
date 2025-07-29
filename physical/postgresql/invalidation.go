package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
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
	p.locallyConsumedInvalidations = make(map[int64]struct{})

	if hook != nil {
		p.logger.Trace("starting invalidation processing...")
		p.invalidateDoneCh = make(chan struct{})
		go p.ProcessInvalidations(p.invalidateDoneCh)
	}
}

func (p *PostgreSQLBackend) HookConfirmInvalidate(hook physical.InvalidateConfirmFunc) {
	p.invalidateLock.Lock()
	defer p.invalidateLock.Unlock()

	p.invalidateConfirm = hook
}

func (p *PostgreSQLBackend) ConfirmedInvalidate(node string, identifier string) {
	p.invalidateLock.Lock()
	defer p.invalidateLock.Unlock()

	idx, err := strconv.ParseInt(identifier, 10, 64)
	if err != nil {
		p.logger.Trace("invalid invalidation", "node", node, "identifier", identifier, "err", err)
		return
	}

	nodes, present := p.consumedInvalidations[idx]
	if !present {
		p.logger.Trace("unknown index to invalidate", "node", node, "identifier", identifier)
		return
	}

	if _, present := nodes[node]; !present {
		p.logger.Trace("node not required to invalidate entry", "node", node, "identifier", identifier)
		return
	}

	nodes[node] = true
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

func (p *PostgreSQLBackend) writeInvalidation(ctx context.Context, txn *sql.Tx, key string) (int64, error) {
	if !p.active.Load() {
		return -1, nil
	}

	switch p.invalidationStrategy {
	case WALTableInvalidationStrategy:
		var identifier int64
		if err := txn.QueryRowContext(ctx, p.tableWalInvalidateQuery, key).Scan(&identifier); err != nil {
			return -1, fmt.Errorf("failed to write invalidation: %w", err)
		}

		return identifier, nil
	default:
		return -1, fmt.Errorf("unknown invalidation strategy: %v", p.invalidationStrategy)
	}

	return -1, nil
}

func (p *PostgreSQLBackend) saveInvalidation(id int64) {
	p.invalidateLock.Lock()
	defer p.invalidateLock.Unlock()

	// We pre-register all standby nodes at the current moment. That way when
	// new ones join, we can require they be up to date after the point where
	// they join and these existing invalidations do not need to be handled by
	// them.
	p.consumedInvalidations[id] = make(map[string]bool, len(p.standbyNodes))
	for nodeId := range p.standbyNodes {
		p.consumedInvalidations[id][nodeId] = false
	}
}

func (p *PostgreSQLBackend) StandbyHeartbeat(id string, checkpoint string, expiry time.Time) {
	p.invalidateLock.Lock()
	defer p.invalidateLock.Unlock()

	entry, present := p.standbyNodes[id]
	if !present {
		entry = &standbyRegistration{}
		p.standbyNodes[id] = entry

		p.logger.Trace("registering new standby node", "uuid", id)
	}

	entry.lastCheckpoint = checkpoint
	entry.expiration = expiry

	p.pruneStandbyNodes()
}

func (p *PostgreSQLBackend) pruneStandbyNodes() {
	var expired []string
	for id, info := range p.standbyNodes {
		if time.Now().After(info.expiration) {
			expired = append(expired, id)
			p.logger.Trace("removing expired standby node")
		}
	}

	for _, id := range expired {
		delete(p.standbyNodes, id)
		for _, consumed := range p.consumedInvalidations {
			delete(consumed, id)
		}
	}
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

		p.invalidateLock.Lock()
		// First prune standby nodes. This gives us greater potential to remove
		// more invalidations.
		p.pruneStandbyNodes()

		// Read invalidations and see if we can clean up any.
		var removable []int64
		for idx, nodes := range p.consumedInvalidations {
			allClear := true
			for _, value := range nodes {
				if !value {
					allClear = false
					break
				}
			}

			if allClear {
				removable = append(removable, idx)
			}
		}
		p.invalidateLock.Unlock()

		if len(removable) == 0 {
			return nil
		}

		p.logger.Trace("removing completed invalidation entries", "count", len(removable))

		query := "DELETE FROM " + p.walTable + " WHERE idx = ANY($1::bigint[])"

		if _, err := p.client.Exec(query, removable); err != nil {
			return fmt.Errorf("failed removing stale invalidations: %w", err)
		}

		p.invalidateLock.Lock()
		for _, idx := range removable {
			delete(p.consumedInvalidations, idx)
		}
		p.invalidateLock.Unlock()

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
		_, seen := p.locallyConsumedInvalidations[index]
		if !seen && p.invalidate != nil {
			p.logger.Trace("invalidating key...", "key", key)
			p.invalidate(key)

			if p.invalidateConfirm != nil {
				p.invalidateConfirm(fmt.Sprintf("%v", index))
			}
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
	p.locallyConsumedInvalidations = seenEntries
	p.invalidateLock.Unlock()

	return nil
}
