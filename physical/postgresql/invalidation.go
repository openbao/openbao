package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/physical"
)

type InvalidationStrategy string

const (
	WALTableInvalidationStrategy InvalidationStrategy = "wal_table"
)

func (p *PostgreSQLBackend) HookInvalidate(hook physical.InvalidateFunc) {
	p.invalidateLock.Lock()
	defer p.invalidateLock.Unlock()

	if p.invalidateDoneCh != nil {
		p.invalidateDoneCh <- struct{}{}
		close(p.invalidateDoneCh)
	}

	p.invalidate = hook

	if hook != nil {
		p.invalidateDoneCh = make(chan struct{})
		go p.ProcessInvalidations(p.invalidateDoneCh)
	}
}

func (p *PostgreSQLBackend) ProcessInvalidations(closeCh chan struct{}) {
	for {
		select {
		case <-closeCh:
			return
		}

		var err error
		switch p.invalidationStrategy {
		case WALTableInvalidationStrategy:
			err = p.doOneTableInvalidation(closeCh)
		}

		if err != nil {
			p.logger.Error("invalidation process failed", "error", err)
		}

		// Provide for backoff; some strategies may be long-running, others
		// might be expecting us to loop for them.
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *PostgreSQLBackend) writeInvalidation(ctx context.Context, path string, txn *sql.Tx) error {
	switch p.invalidationStrategy {
	case WALTableInvalidationStrategy:
		_, err := txn.ExecContext(ctx, p.tableWalInvalidateQuery, path)
		if err != nil {
			return fmt.Errorf("failed to write invalidation: %w", err)
		}
	default:
		return fmt.Errorf("unknown invalidation strategy: %v", p.invalidationStrategy)
	}

	return nil
}

func (p *PostgreSQLBackend) doOneTableInvalidation(closeCh chan struct{}) error {
	return nil
}
