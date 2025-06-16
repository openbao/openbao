package vault

import (
	"context"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// WithTransaction will add a transaction to the context (if possible)
func (m *ExpirationManager) WithTransaction(
	ctx context.Context,
	callbackFn func(context.Context) error) error {

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	var tx logical.Transaction
	barrierView := m.leaseView(ctx, ns)
	if bvtx, ok := barrierView.(TransactionalBarrierView); ok {
		tx, err = bvtx.BeginTx(ctx)
		if err != nil {
			// If we fail to begin a transaction, log and return the original view
			m.logger.Error("failed to begin transaction for lease view", "error", err)
		}
	}

	txCtx := context.WithValue(ctx, logical.TransactionContextKey, tx)

	if err := callbackFn(txCtx); err != nil {
		if tx != nil {
			if err := tx.Rollback(ctx); err != nil {
				m.logger.Error("failed to rollback lease view transaction", "error", err)
			}
		}
		return err
	} else {
		if tx != nil {
			if err := tx.Commit(ctx); err != nil {
				m.logger.Error("failed to commit lease view transaction", "error", err)
			}
		}
		return nil
	}
}
