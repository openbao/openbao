// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cassandra

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gocql/gocql"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/require"
)

func TestIsNoHosts(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":             {err: nil, want: false},
		"unrelated":       {err: errors.New("boom"), want: false},
		"direct":          {err: gocql.ErrNoConnections, want: true},
		"wrapped":         {err: fmt.Errorf("exec: %w", gocql.ErrNoConnections), want: true},
		"string only":     {err: errors.New("query failed: " + gocql.ErrNoConnections.Error()), want: true},
		"multierror":      {err: multierror.Append(errors.New("a"), gocql.ErrNoConnections), want: true},
		"other gocql err": {err: gocql.ErrTimeoutNoResponse, want: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, isNoHosts(tc.err))
		})
	}
}

// newUnreachableCassandra returns an initialized plugin whose createSession fails fast (connection refused).
func newUnreachableCassandra() *Cassandra {
	c := new()
	c.Initialized = true
	c.Hosts = "127.0.0.1"
	c.Port = 1
	c.Username = "u"
	c.Password = "p"
	c.connectTimeout = 200 * time.Millisecond
	return c
}

func TestWithSession_NotInitialized(t *testing.T) {
	c := new()
	called := false
	err := c.withSession(context.Background(), func(*gocql.Session) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.False(t, called)
}

func TestWithSession_Success(t *testing.T) {
	c := newUnreachableCassandra()
	sess := &gocql.Session{}
	c.session = sess

	calls := 0
	err := c.withSession(context.Background(), func(s *gocql.Session) error {
		calls++
		require.Same(t, sess, s)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Same(t, sess, c.session)
	require.False(t, sess.Closed())
}

func TestWithSession_OtherErrorNoRetry(t *testing.T) {
	c := newUnreachableCassandra()
	sess := &gocql.Session{}
	c.session = sess
	want := errors.New("syntax error")

	calls := 0
	err := c.withSession(context.Background(), func(*gocql.Session) error {
		calls++
		return want
	})
	require.ErrorIs(t, err, want)
	require.Equal(t, 1, calls)
	require.Same(t, sess, c.session, "session must be kept")
	require.False(t, sess.Closed())
}

func TestWithSession_NoHostsDropsSessionAndReportsBothErrors(t *testing.T) {
	c := newUnreachableCassandra()
	sess := &gocql.Session{}
	c.session = sess

	calls := 0
	err := c.withSession(context.Background(), func(*gocql.Session) error {
		calls++
		return gocql.ErrNoConnections
	})
	require.Error(t, err)
	require.Equal(t, 1, calls, "fn must not be retried when reconnecting fails")
	require.True(t, sess.Closed(), "broken session must be closed")
	require.Nil(t, c.session, "broken session must be dropped")
	require.ErrorIs(t, err, gocql.ErrNoConnections)
	require.Contains(t, err.Error(), "error creating session")
}

// TestWithSession_ReconnectsOnNoHosts needs a container (docker or podman) and covers the successful retry:
// the first attempt reports no hosts, so the session is replaced and fn runs again on a working session.
func TestWithSession_ReconnectsOnNoHosts(t *testing.T) {
	db, cleanup := getCassandra(t, 4)
	defer cleanup()

	db.Lock()
	defer db.Unlock()

	first, err := db.getConnection(context.Background())
	require.NoError(t, err)

	var sessions []*gocql.Session
	err = db.withSession(context.Background(), func(s *gocql.Session) error {
		sessions = append(sessions, s)
		if len(sessions) == 1 {
			return gocql.ErrNoConnections
		}
		return s.Query(`SELECT release_version FROM system.local`).Exec()
	})
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	require.Same(t, first, sessions[0])
	require.NotSame(t, sessions[0], sessions[1])
	require.True(t, first.Closed())
	require.Same(t, sessions[1], db.session)
	require.False(t, sessions[1].Closed())
}
