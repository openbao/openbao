// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Package scheduling computes occurrences of periodical or cron-like schedules,
// optionally paired with a window during which a missed occurrence may still happen.
package scheduling

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gdgvda/cron"
)

// MinPeriod is the shortest period for a periodic schedule, and the shortest
// time accepted between two occurrences of a cron schedule.
const MinPeriod = 5 * time.Second

// MinWindow is the shortest non window accepted.
const MinWindow = 3600 * time.Second

// maxWindowIterations bounds the number of occurrences to walks through when
// computing if an occurence is due, i.e. still in a window after `next` occurrence.
const maxWindowIterations = 100_000

// parseOptions accepts standard 5-field cron expressions, an optional leading
// seconds field, and descriptors such as @daily or @every <duration>.
const parseOptions = cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor

// Scheduler creates schedules and computes their occurrences.
type Scheduler interface {

	// NextOccurrence returns time when next occurrence is expected
	NextOccurrence() time.Time

	// IsDue returns True if scheduled occurence must happen.
	IsDue() bool

	// Called when occurrence happens, returns next expected occurrence.
	Occurrence() time.Time
}

type Schedulable interface {
	// period of periodic scheduling
	GetPeriod() time.Duration
	SetPeriod(period time.Duration)

	// CronExpr is the cron expression the schedule was built from. Periodic
	// schedules are stored as "@every <period>".
	GetCronExpr() string
	SetCronExpr(cronExpr string)

	// window is how long after an occurrence it is still considered in its
	// occurrence window. Zero means there is no window.
	GetWindow() time.Duration
	SetWindow(window time.Duration)

	// next expected occurrence, computed at setup and on every occurrence
	// note that next may be in the past for some time,
	// and jump back to the future when Happening is invoked
	GetNext() time.Time
	SetNext(next time.Time)

	// last occurrence, zero until it happens
	GetLast() time.Time
	SetLast(last time.Time)
}

// DefaultScheduler is the default Scheduler implementation.
type DefaultScheduler struct {
	now func() time.Time

	// Flag to adjust behaviour for non-periodic (cron) schedulers
	periodic bool
	// Schedule parser from the Cron library
	parser *cron.DefaultParser
	// Cron library schedule, nil if and _only_ if no schedule have been set
	sched cron.Schedule

	// Schedulable holds everything meant to persist between occurrences
	Schedulable
}

// make explicit DefaultScheduler implements Scheduler for compile time checks
var _ Scheduler = (*DefaultScheduler)(nil)

func (d *DefaultScheduler) parseCronExpr(cronExpr string) error {
	cronSched, err := d.parser.Parse(cronExpr)
	if err != nil {
		return fmt.Errorf("invalid cron expression %q: %w", cronExpr, err)
	}
	if interval := cronSched.MinInterval(); interval < MinPeriod {
		return fmt.Errorf("invalid cron expression %q: occurrences %s apart are closer than the minimum of %s", cronExpr, interval, MinPeriod)
	}
	d.sched = cronSched
	return nil
}

func NewDefaultScheduler(schedulable Schedulable) (*DefaultScheduler, error) {
	parser, err := cron.NewDefaultParser(parseOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create cron parser: %w", err)
	}

	newSched := DefaultScheduler{
		parser:      parser,
		now:         time.Now,
		Schedulable: schedulable,
	}

	// Schedulable may be pre-configured

	// with a cron expression. If so, parse it.
	period := newSched.GetPeriod()
	cronExpr := newSched.GetCronExpr()
	window := newSched.GetWindow()
	if period != 0 {
		if err := newSched.setPeriodic(period, window); err != nil {
			return nil, fmt.Errorf("failed to create DefaultScheduler on pre-existing schedule: %w", err)
		}
	} else if cronExpr != "" {
		if err := newSched.setWithCronExp(cronExpr, window); err != nil {
			return nil, fmt.Errorf("failed to create DefaultScheduler on pre-existing schedule: %w", err)
		}
	}

	return &newSched, nil
}

// setWithCronExp sets the cron expression and window duration.
func (d *DefaultScheduler) setWithCronExp(cronExpr string, window time.Duration) error {
	cronExpr = strings.TrimSpace(cronExpr)

	prevCronExpr := d.GetCronExpr()
	prevWindow := d.GetWindow()

	newSchedule := prevCronExpr != cronExpr || prevWindow != window

	if newSchedule {
		if cronExpr == "" {
			return errors.New("empty cron expression")
		}
		if window < 0 {
			return fmt.Errorf("negative window: %s", window)
		}
		if window > 0 && window < MinWindow {
			return fmt.Errorf("window too small: %s < %s", window, MinWindow)
		}
	}

	if d.sched == nil || newSchedule {
		err := d.parseCronExpr(cronExpr)
		if err != nil {
			return err
		}
	}

	if newSchedule {
		d.SetCronExpr(cronExpr)
		d.SetWindow(window)
	}

	return nil
}

// setPeriodic checks period and window validity and handover to setWithCronExp.
func (d *DefaultScheduler) setPeriodic(period time.Duration, window time.Duration) error {
	if period < MinPeriod {
		return fmt.Errorf("period %s is shorter than the minimum of %s", period, MinPeriod)
	}
	period = period.Round(time.Second)
	if window >= period {
		return fmt.Errorf("window %s must be shorter than period %s", window, period)
	}
	d.SetPeriod(period)
	d.periodic = true

	return d.setWithCronExp("@every "+period.String(), window)
}

// NextOccurrence returns time of the next future occurrence
// and sets it to the scheduler as a side effect
func (d *DefaultScheduler) NextOccurrence() time.Time {
	now := d.now()
	next := d.nextOccurrenceAfter(now)
	d.SetNext(next)
	return next
}

// NextOccurrence returns time of the next occurrence after given time.
func (d *DefaultScheduler) nextOccurrenceAfter(when time.Time) time.Time {
	if d.sched == nil {
		return time.Time{}
	}

	last := d.GetLast()

	if d.periodic && !last.IsZero() {
		var lastPossibleOccurrence time.Time
		period := d.GetPeriod()
		// periodic schedulers must keep aligned on previous occurrence
		if when.Before(last) {
			// can happen in case of non-monotonic clock
			// align backward
			timeBeforeLastOccurrence := last.Sub(when)
			lastPossibleOccurrence = last.Add(
				-timeBeforeLastOccurrence.Truncate(period) - period)
		} else {
			// normal case
			elapsedSinceLastOccurrence := when.Sub(last)
			lastPossibleOccurrence = last.Add(
				elapsedSinceLastOccurrence.Truncate(period))
		}
		return d.sched.Next(lastPossibleOccurrence)
	} else {
		// otherwise compute next occurrence after given time
		return d.sched.Next(when)
	}
}

// IsDue returns True when job is expected to be done now.
// Code invoking this method is expected to start job and call
// Happening() right after any positive result.
func (d *DefaultScheduler) IsDue() bool {
	now := d.now()

	// eliminate corner cases
	if d.sched == nil || now.Before(d.GetLast()) {
		return false
	}

	// should have happend, no window set,
	if d.GetWindow() == 0 && now.After(d.GetNext()) {
		return true
	}

	// should have happend, but within given window
	if d.GetWindow() > 0 && now.After(d.GetNext()) {
		occ := d.GetNext()
		for i := 0; !occ.After(now); i++ {
			if now.Before(occ.Add(d.GetWindow())) {
				return true
			}
			// Else in the unlikely case `now` is past first occurrence window,
			// which could happen in case of suspend or migration, iterate
			// over passed occurrences until window is found.
			if i >= maxWindowIterations {
				// In case of (impossibly) long time since last call to
				// Happening() or Set*(), limit iterations and recover.
				// Catch back and wait for next occurrence.
				d.SetNext(d.sched.Next(now))
				// Assume not being in window anyhow.
				return false
			}
			occ = d.sched.Next(occ)

			// Note: iterating until meeting current window is suboptimal.
			// Best would be to use a cron paser and scheduler library
			// that supports computing Previous() occurrence such as
			// github.com/adhocore/gronx . Unfortunately gronx doesn't
			// support TimeZone specification in cron expression at the time
			// of writing impacting compatibility with existing
			// implementation(s) of rotation_schedule + rotation_window.

		}
	}

	// Not due
	return false
}

// Occurrence records that the occurrence takes place now it becomes the
// last occurrence, and the next occurrence is computed from it.
func (d *DefaultScheduler) Occurrence() time.Time {
	now := d.now()

	// compute next occurrence before changing last to avoid drift
	next := d.nextOccurrenceAfter(now)

	d.SetLast(now)
	d.SetNext(next)
	return next
}
