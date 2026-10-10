// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package scheduling

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func at(hour, minute int) time.Time {
	return time.Date(2026, 1, 1, hour, minute, 0, 0, time.UTC)
}

// testSchedulable is a minimal in-memory Schedulable.
type testSchedulable struct {
	period   time.Duration
	cronExpr string
	window   time.Duration
	next     time.Time
	last     time.Time
}

var _ Schedulable = (*testSchedulable)(nil)

func (s *testSchedulable) GetPeriod() time.Duration       { return s.period }
func (s *testSchedulable) SetPeriod(period time.Duration) { s.period = period }
func (s *testSchedulable) GetCronExpr() string            { return s.cronExpr }
func (s *testSchedulable) SetCronExpr(cronExpr string)    { s.cronExpr = cronExpr }
func (s *testSchedulable) GetWindow() time.Duration       { return s.window }
func (s *testSchedulable) SetWindow(w time.Duration)      { s.window = w }
func (s *testSchedulable) GetNext() time.Time             { return s.next }
func (s *testSchedulable) SetNext(next time.Time)         { s.next = next }
func (s *testSchedulable) GetLast() time.Time             { return s.last }
func (s *testSchedulable) SetLast(last time.Time)         { s.last = last }

func newTestScheduler(t *testing.T) *DefaultScheduler {
	t.Helper()
	d, err := NewDefaultScheduler(&testSchedulable{})
	require.NoError(t, err)
	return d
}

// happenAt calls Occurrence with the scheduler clock set to when, then restores
// the real clock.
func happenAt(d *DefaultScheduler, when time.Time) {
	d.now = func() time.Time { return when }
	d.Occurrence()
}

// fixClock sets the scheduler clock to when.
func fixClock(d *DefaultScheduler, when time.Time) {
	d.now = func() time.Time { return when }
}

func TestSetWithCronExp(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		window   time.Duration
		wantErr  bool
		wantExpr string
	}{
		{name: "standard", expr: "0 * * * *", wantExpr: "0 * * * *"},
		{name: "trimmed", expr: "  0 * * * *  ", wantExpr: "0 * * * *"},
		{name: "with seconds", expr: "30 0 * * * *", wantExpr: "30 0 * * * *"},
		{name: "descriptor", expr: "@daily", wantExpr: "@daily"},
		{name: "every", expr: "@every 1h", wantExpr: "@every 1h"},
		{name: "every minimum period", expr: "@every 5s", wantExpr: "@every 5s"},
		{name: "every too short", expr: "@every 4s", wantErr: true},
		{name: "seconds at minimum period", expr: "*/5 * * * * *", wantExpr: "*/5 * * * * *"},
		{name: "every second", expr: "* * * * * *", wantErr: true},
		{name: "seconds step too short", expr: "*/4 * * * * *", wantErr: true},
		{name: "seconds too close, rare occurrences", expr: "0,3 0 0 29 2 *", wantErr: true},
		{name: "seconds too close across minutes", expr: "0,57 * * * * *", wantErr: true},
		{name: "seconds far enough across minutes", expr: "0,55 * * * * *", wantExpr: "0,55 * * * * *"},
		{name: "seconds too close, no consecutive minutes", expr: "0,57 */2 * * * *", wantExpr: "0,57 */2 * * * *"},
		{name: "seconds too close across hours", expr: "0,57 59,0 * * * *", wantErr: true},
		{name: "seconds too close, no consecutive hours", expr: "0,57 59,0 */2 * * *", wantExpr: "0,57 59,0 */2 * * *"},
		{name: "cron time zone", expr: "CRON_TZ=Asia/Tokyo 30 04 * * *", wantExpr: "CRON_TZ=Asia/Tokyo 30 04 * * *"},
		{name: "time zone", expr: "TZ=UTC 0 0 * * *", wantExpr: "TZ=UTC 0 0 * * *"},
		{name: "time zone descriptor", expr: "CRON_TZ=Europe/Paris @daily", wantExpr: "CRON_TZ=Europe/Paris @daily"},
		{name: "unknown time zone", expr: "CRON_TZ=Nowhere/Land 0 0 * * *", wantErr: true},
		{name: "time zone only", expr: "CRON_TZ=UTC", wantErr: true},
		{name: "with window", expr: "0 0 * * *", window: 2 * time.Hour, wantExpr: "0 0 * * *"},
		{name: "minimum window", expr: "0 0 * * *", window: MinWindow, wantExpr: "0 0 * * *"},
		{name: "window too small", expr: "0 * * * *", window: 10 * time.Minute, wantErr: true},
		{name: "negative window", expr: "0 * * * *", window: -time.Second, wantErr: true},
		{name: "garbage", expr: "not a cron", wantErr: true},
		{name: "empty", expr: "", wantErr: true},
		{name: "blank", expr: "   ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestScheduler(t)
			err := d.setWithCronExp(tt.expr, tt.window)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, d.sched)
				require.Empty(t, d.GetCronExpr())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantExpr, d.GetCronExpr())
			require.Equal(t, tt.window, d.GetWindow())
			require.True(t, d.GetLast().IsZero())
		})
	}
}

func TestNewDefaultScheduler_Preconfigured(t *testing.T) {
	tests := []struct {
		name     string
		stored   testSchedulable
		wantErr  bool
		wantExpr string
		wantNext time.Time
		when     time.Time
	}{
		{
			name: "cron expression",
			stored: testSchedulable{
				cronExpr: "0 * * * *",
				last:     at(8, 30),
				next:     at(9, 0),
			},
			wantExpr: "0 * * * *",
			wantNext: at(9, 0),
			when:     at(8, 25),
		},
		{
			name: "cron expression with window",
			stored: testSchedulable{
				cronExpr: "0 0 * * *",
				window:   2 * time.Hour,
				last:     at(0, 30),
			},
			wantExpr: "0 0 * * *",
			wantNext: at(0, 0).Add(24 * time.Hour),
		},
		{
			name: "period, missing next computed from last",
			stored: testSchedulable{
				period: time.Hour,
				last:   at(8, 50),
			},
			wantExpr: "@every 1h0m0s",
			wantNext: at(9, 50),
		},
		{
			name: "period, next overwritten",
			stored: testSchedulable{
				period: time.Hour,
				last:   at(8, 50),
				next:   at(10, 0),
			},
			wantExpr: "@every 1h0m0s",
			wantNext: at(9, 50),
			when:     at(9, 11),
		},
		{
			name: "period, last in the future",
			stored: testSchedulable{
				period: time.Hour,
				last:   at(8, 50),
				next:   at(10, 0),
			},
			wantExpr: "@every 1h0m0s",
			wantNext: at(8, 50),
			when:     at(8, 30),
		},
		{
			name: "invalid cron expression",
			stored: testSchedulable{
				cronExpr: "not a cron",
			},
			wantErr: true,
		},
		{
			name: "cron expression occurring too often",
			stored: testSchedulable{
				cronExpr: "* * * * * *",
			},
			wantErr: true,
		},
		{
			name: "period too short",
			stored: testSchedulable{
				period: time.Second,
			},
			wantErr: true,
		},
		{
			name: "period window too small",
			stored: testSchedulable{
				period: 2 * time.Hour,
				window: time.Minute,
			},
			wantErr: true,
		},
		{
			name: "period window longer than period",
			stored: testSchedulable{
				period: 2 * time.Hour,
				window: 3 * time.Hour,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stored := tt.stored
			d, err := NewDefaultScheduler(&stored)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, d)
				return
			}
			if !tt.stored.last.IsZero() {
				happenAt(d, tt.stored.last)
			}
			if !tt.when.IsZero() {
				fixClock(d, tt.when)
			}
			require.NoError(t, err)
			require.NotNil(t, d.sched)
			require.Equal(t, tt.wantExpr, stored.cronExpr)
			require.Equal(t, tt.stored.window, stored.window)
			require.Equal(t, tt.stored.last, stored.last)
			require.Equal(t, tt.wantNext, d.NextOccurrence())
		})
	}
}

func TestNewDefaultScheduler_Unconfigured(t *testing.T) {
	stored := testSchedulable{}
	d, err := NewDefaultScheduler(&stored)
	require.NoError(t, err)
	require.Nil(t, d.sched)
	require.Equal(t, testSchedulable{}, stored)
}

func TestSetWithCronExp_NextFromLast(t *testing.T) {
	d := newTestScheduler(t)
	fixClock(d, at(12, 0))
	d.SetLast(at(8, 50))

	// New schedule: next is computed from last, not from now.
	require.NoError(t, d.setWithCronExp("0 * * * *", 0))
	require.Equal(t, at(13, 0), d.NextOccurrence())

	// Periodic schedules are relative to last as well.
	require.NoError(t, d.setPeriodic(2*time.Hour, 0))
	require.Equal(t, "@every 2h0m0s", d.GetCronExpr())
	require.Equal(t, at(12, 50), d.NextOccurrence())
}

func TestSetWithCronExp_TimeZone(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	require.NoError(t, err)

	d := newTestScheduler(t)
	require.NoError(t, d.setWithCronExp("CRON_TZ=Asia/Tokyo 30 04 * * *", 0))

	// 2026-01-01 00:00 UTC is 09:00 in Tokyo, so the next 04:30 there is on
	// the following day, which is 19:30 UTC the same day
	happenAt(d, at(0, 0))
	require.True(t, time.Date(2026, 1, 2, 4, 30, 0, 0, tokyo).Equal(d.GetNext()), "got %s", d.GetNext())
	require.True(t, at(19, 30).Equal(d.GetNext()), "got %s", d.GetNext())
}

func TestSetWithCronExp_ErrorKeepsPreviousSchedule(t *testing.T) {
	d := newTestScheduler(t)
	require.NoError(t, d.setWithCronExp("0 0 * * *", 2*time.Hour))
	sched, next := d.sched, d.GetNext()

	require.Error(t, d.setWithCronExp("not a cron", 0))
	require.Error(t, d.setWithCronExp("0 * * * *", time.Minute))

	require.Equal(t, "0 0 * * *", d.GetCronExpr())
	require.Equal(t, 2*time.Hour, d.GetWindow())
	require.Equal(t, sched, d.sched)
	require.Equal(t, next, d.GetNext())
}

func TestSetPeriodic(t *testing.T) {
	tests := []struct {
		name     string
		period   time.Duration
		window   time.Duration
		wantErr  bool
		wantExpr string
	}{
		{name: "with window", period: 2 * time.Hour, window: time.Hour, wantExpr: "@every 2h0m0s"},
		{name: "minimum", period: MinPeriod, wantExpr: "@every 5s"},
		{name: "rounded", period: 90*time.Second + 400*time.Millisecond, wantExpr: "@every 1m30s"},
		{name: "too short", period: 4 * time.Second, wantErr: true},
		{name: "zero", period: 0, wantErr: true},
		{name: "negative", period: -time.Hour, wantErr: true},
		{name: "window too small", period: time.Hour, window: 30 * time.Minute, wantErr: true},
		{name: "window equals period", period: 2 * time.Hour, window: 2 * time.Hour, wantErr: true},
		{name: "window longer than period", period: 2 * time.Hour, window: 3 * time.Hour, wantErr: true},
		{name: "negative window", period: time.Hour, window: -time.Second, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestScheduler(t)
			err := d.setPeriodic(tt.period, tt.window)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, d.sched)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantExpr, d.GetCronExpr())
			require.Equal(t, tt.window, d.GetWindow())
			require.True(t, d.GetLast().IsZero())
		})
	}
}

func TestSetPeriodic_NextTruncatesToSecond(t *testing.T) {
	d := newTestScheduler(t)
	require.NoError(t, d.setPeriodic(time.Hour, 0))

	require.Zero(t, d.GetNext().Nanosecond())
	require.Equal(t, at(14, 0), d.sched.Next(at(13, 0).Add(999*time.Millisecond)))
}

func TestHapening(t *testing.T) {
	cronSched := newTestScheduler(t)
	require.NoError(t, cronSched.setWithCronExp("0 * * * *", 0))
	periodic := newTestScheduler(t)
	require.NoError(t, periodic.setPeriodic(time.Hour, 0))

	happened := at(8, 50)

	happenAt(cronSched, happened)
	require.Equal(t, happened, cronSched.GetLast())
	require.Equal(t, at(9, 0), cronSched.GetNext())

	happenAt(periodic, happened)
	require.Equal(t, happened, periodic.GetLast())
	require.Equal(t, at(9, 50), periodic.GetNext())
}

func TestNextOccurrence_FixedClock(t *testing.T) {
	cronSched := newTestScheduler(t)
	require.NoError(t, cronSched.setWithCronExp("0 * * * *", 0))
	happenAt(cronSched, at(11, 0))
	periodic := newTestScheduler(t)
	require.NoError(t, periodic.setPeriodic(time.Hour, 0))
	happenAt(periodic, at(11, 0))

	tests := []struct {
		name  string
		sched *DefaultScheduler
		when  time.Time
		want  time.Time
	}{
		{name: "cached next", sched: cronSched, when: at(11, 30), want: at(12, 0)},
		{name: "next equals when", sched: cronSched, when: at(12, 0), want: at(13, 0)},
		{name: "next missed", sched: cronSched, when: at(12, 30), want: at(13, 0)},
		{name: "periodic cached next", sched: periodic, when: at(11, 30), want: at(12, 0)},
		{name: "periodic next missed", sched: periodic, when: at(12, 30), want: at(13, 0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			last := tt.sched.GetLast()
			fixClock(tt.sched, tt.when)
			require.Equal(t, tt.want, tt.sched.NextOccurrence())
			require.Equal(t, last, tt.sched.GetLast())
		})
	}
}

func TestIsDue_Window(t *testing.T) {
	newSched := func(expr string, window time.Duration) *DefaultScheduler {
		d := newTestScheduler(t)
		require.NoError(t, d.setWithCronExp(expr, window))
		happenAt(d, at(8, 30))
		return d
	}
	s := newSched("0 */3 * * *", time.Hour)
	noWindow := newSched("0 */3 * * *", 0)
	periodic := newSched("@every 3h", time.Hour)

	require.Equal(t, at(9, 0), s.GetNext())
	require.Equal(t, at(11, 30), periodic.GetNext())

	tests := []struct {
		name  string
		sched *DefaultScheduler
		when  time.Time
		want  bool
	}{
		{name: "before next", sched: s, when: at(8, 59), want: false},
		{name: "at next excluded", sched: s, when: at(9, 0), want: false},
		{name: "just after next", sched: s, when: at(9, 0).Add(time.Second), want: true},
		{name: "within first window", sched: s, when: at(9, 30), want: true},
		{name: "first window end excluded", sched: s, when: at(10, 0), want: false},
		{name: "between windows", sched: s, when: at(11, 30), want: false},
		{name: "within later window", sched: s, when: at(12, 30), want: true},
		{name: "no window, before next", sched: noWindow, when: at(8, 59), want: false},
		{name: "no window, missed", sched: noWindow, when: at(11, 30), want: true},
		{name: "periodic within first window", sched: periodic, when: at(12, 0), want: true},
		{name: "periodic between windows", sched: periodic, when: at(13, 0), want: false},
		{name: "periodic within later window", sched: periodic, when: at(14, 45), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixClock(tt.sched, tt.when)
			require.Equal(t, tt.want, tt.sched.IsDue())
		})
	}
}

func TestIsDue_IterationCap(t *testing.T) {
	d := newTestScheduler(t)
	require.NoError(t, d.setWithCronExp("*/5 * * * * *", MinWindow))
	fixClock(d, at(12, 30))

	// A recent next occurrence is within its window.
	d.SetNext(at(12, 0))
	require.True(t, d.IsDue())

	// Walking ten days of occurrences every MinPeriod exceeds the cap: not
	// due, and next catches back up with now.
	d.SetNext(at(12, 0).Add(-240 * time.Hour))
	require.False(t, d.IsDue())
	require.Equal(t, at(12, 30).Add(MinPeriod), d.GetNext())
}

func TestIsDue(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name   string
		expr   string
		window time.Duration
		last   time.Time
		next   time.Time
		want   bool
	}{
		{name: "next in future", expr: "@every 24h", next: now.Add(time.Hour), want: false},
		{name: "last in future", expr: "@every 24h", last: now.Add(time.Hour), next: now.Add(-time.Hour), want: false},
		{name: "no window, missed, never happened", expr: "@every 24h", next: now.Add(-time.Hour), want: true},
		{name: "no window, missed after happening", expr: "@every 24h", last: now.Add(-25 * time.Hour), next: now.Add(-time.Hour), want: true},
		{name: "window, in first window", expr: "@every 24h", window: time.Hour, last: now.Add(-24*time.Hour - 30*time.Minute), next: now.Add(-30 * time.Minute), want: true},
		{name: "window, first window closed", expr: "@every 24h", window: time.Hour, last: now.Add(-26 * time.Hour), next: now.Add(-2 * time.Hour), want: false},
		{name: "window, in later window", expr: "@every 24h", window: time.Hour, last: now.Add(-48*time.Hour - 30*time.Minute), next: now.Add(-24*time.Hour - 30*time.Minute), want: true},
		{name: "window, in first window, never happened", expr: "@every 24h", window: time.Hour, next: now.Add(-30 * time.Minute), want: true},
		{name: "window, next in future", expr: "@every 24h", window: time.Hour, last: now.Add(-time.Hour), next: now.Add(23 * time.Hour), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestScheduler(t)
			require.NoError(t, d.setWithCronExp(tt.expr, tt.window))
			d.SetLast(tt.last)
			d.SetNext(tt.next)
			require.Equal(t, tt.want, d.IsDue())
		})
	}
}

func TestIsDue_AfterHapening(t *testing.T) {
	d := newTestScheduler(t)
	require.NoError(t, d.setWithCronExp("@every 24h", 0))

	d.SetNext(time.Now().Add(-time.Hour))
	require.True(t, d.IsDue())

	d.Occurrence()
	require.False(t, d.IsDue())
}
func TestUnsetScheduler(t *testing.T) {
	d := newTestScheduler(t)

	require.True(t, d.NextOccurrence().IsZero())
	fixClock(d, at(12, 0))
	require.True(t, d.NextOccurrence().IsZero())

	happenAt(d, at(12, 0))
	require.Equal(t, at(12, 0), d.GetLast())
	require.True(t, d.GetNext().IsZero())
}
