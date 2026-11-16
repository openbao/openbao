// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/openbao/openbao/sdk/v2/physical"
)

var _ physical.ReplicationIndexBackend = &PostgreSQLBackend{}

const lsnIndexQuery = `
SELECT value.index::varchar
FROM (
	SELECT CASE pg_is_in_recovery()
	WHEN true
	THEN pg_last_wal_receive_lsn()
	ELSE pg_current_wal_lsn()
	END
	AS index
)
AS value;
`

func (p *PostgreSQLBackend) AppliedReplicationIndex(ctx context.Context) (string, error) {
	var index string
	if err := p.client.QueryRowContext(ctx, lsnIndexQuery).Scan(&index); err != nil {
		return "", fmt.Errorf("getting WAL LSN failed: %w", err)
	}

	return index, nil
}

func (p *PostgreSQLBackend) GreaterEqualReplicationIndex(ctx context.Context, left string, right string) (bool, error) {
	leftInt, err := indexToUint64(left)
	if err != nil {
		return false, fmt.Errorf("error parsing left: %w", err)
	}

	rightInt, err := indexToUint64(right)
	if err != nil {
		return false, fmt.Errorf("error parsing right: %w", err)
	}

	return leftInt >= rightInt, nil
}

func indexToUint64(index string) (uint64, error) {
	if strings.Count(index, "/") != 1 {
		return 0, fmt.Errorf("expected PG WAL LSN to contain exactly one slash: was %q", index)
	}

	parts := strings.SplitN(index, "/", 2)

	// See https://pgpedia.info/x/xlogrecptr.html for naming info.
	xlogid, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PG WAL LSN's log file number: %w", err)
	}

	xrecoff, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PG WAL LSN's byte offset: %w", err)
	}

	return xlogid<<32 | xrecoff, nil
}
