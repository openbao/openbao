// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestExecConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *ExecConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&ExecConfig{},
		},
		{
			"copy",
			&ExecConfig{
				Command:      []string{"command"},
				Enabled:      Bool(true),
				Env:          &EnvConfig{Pristine: Bool(true)},
				KillSignal:   Signal(syscall.SIGINT),
				KillTimeout:  TimeDuration(10 * time.Second),
				ReloadSignal: Signal(syscall.SIGINT),
				Splay:        TimeDuration(10 * time.Second),
				Timeout:      TimeDuration(10 * time.Second),
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.a.Copy()
			if !reflect.DeepEqual(tc.a, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.a, r)
			}
		})
	}
}

func TestExecConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *ExecConfig
		b    *ExecConfig
		r    *ExecConfig
	}{
		{
			"nil_a",
			nil,
			&ExecConfig{},
			&ExecConfig{},
		},
		{
			"nil_b",
			&ExecConfig{},
			nil,
			&ExecConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&ExecConfig{},
			&ExecConfig{},
			&ExecConfig{},
		},
		{
			"command_overrides",
			&ExecConfig{Command: []string{"command"}},
			&ExecConfig{Command: []string{}},
			&ExecConfig{Command: []string{}},
		},
		{
			"command_empty_one",
			&ExecConfig{Command: []string{"command"}},
			&ExecConfig{},
			&ExecConfig{Command: []string{"command"}},
		},
		{
			"command_empty_two",
			&ExecConfig{},
			&ExecConfig{Command: []string{"command"}},
			&ExecConfig{Command: []string{"command"}},
		},
		{
			"command_same",
			&ExecConfig{Command: []string{"command"}},
			&ExecConfig{Command: []string{"command"}},
			&ExecConfig{Command: []string{"command"}},
		},
		{
			"enabled_overrides",
			&ExecConfig{Enabled: Bool(true)},
			&ExecConfig{Enabled: Bool(false)},
			&ExecConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&ExecConfig{Enabled: Bool(true)},
			&ExecConfig{},
			&ExecConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&ExecConfig{},
			&ExecConfig{Enabled: Bool(true)},
			&ExecConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&ExecConfig{Enabled: Bool(true)},
			&ExecConfig{Enabled: Bool(true)},
			&ExecConfig{Enabled: Bool(true)},
		},
		{
			"env_overrides",
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(false)}},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(false)}},
		},
		{
			"env_empty_one",
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
			&ExecConfig{},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
		},
		{
			"env_empty_two",
			&ExecConfig{},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
		},
		{
			"env_same",
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
			&ExecConfig{Env: &EnvConfig{Pristine: Bool(true)}},
		},
		{
			"kill_signal_overrides",
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
			&ExecConfig{KillSignal: Signal(syscall.SIGUSR1)},
			&ExecConfig{KillSignal: Signal(syscall.SIGUSR1)},
		},
		{
			"kill_signal_empty_one",
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
			&ExecConfig{},
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
		},
		{
			"kill_signal_empty_two",
			&ExecConfig{},
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
		},
		{
			"kill_signal_same",
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
			&ExecConfig{KillSignal: Signal(syscall.SIGINT)},
		},
		{
			"kill_timeout_overrides",
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
			&ExecConfig{KillTimeout: TimeDuration(0 * time.Second)},
			&ExecConfig{KillTimeout: TimeDuration(0 * time.Second)},
		},
		{
			"kill_timeout_empty_one",
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
			&ExecConfig{},
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"kill_timeout_empty_two",
			&ExecConfig{},
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"kill_timeout_same",
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
			&ExecConfig{KillTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"reload_signal_overrides",
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGUSR1)},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGUSR1)},
		},
		{
			"reload_signal_empty_one",
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
			&ExecConfig{},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
		},
		{
			"reload_signal_empty_two",
			&ExecConfig{},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
		},
		{
			"reload_signal_same",
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
			&ExecConfig{ReloadSignal: Signal(syscall.SIGINT)},
		},
		{
			"splay_overrides",
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
			&ExecConfig{Splay: TimeDuration(0 * time.Second)},
			&ExecConfig{Splay: TimeDuration(0 * time.Second)},
		},
		{
			"splay_empty_one",
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
			&ExecConfig{},
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
		},
		{
			"splay_empty_two",
			&ExecConfig{},
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
		},
		{
			"splay_same",
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
			&ExecConfig{Splay: TimeDuration(10 * time.Second)},
		},
		{
			"timeout_overrides",
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
			&ExecConfig{Timeout: TimeDuration(0 * time.Second)},
			&ExecConfig{Timeout: TimeDuration(0 * time.Second)},
		},
		{
			"timeout_empty_one",
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
			&ExecConfig{},
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
		},
		{
			"timeout_empty_two",
			&ExecConfig{},
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
		},
		{
			"timeout_same",
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
			&ExecConfig{Timeout: TimeDuration(10 * time.Second)},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			r := tc.a.Merge(tc.b)
			if !reflect.DeepEqual(tc.r, r) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.r, r)
			}
		})
	}
}

func TestExecConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *ExecConfig
		r    *ExecConfig
	}{
		{
			"empty",
			&ExecConfig{},
			&ExecConfig{
				Command: []string{},
				Enabled: Bool(false),
				Env: &EnvConfig{
					Allowlist:           []string{},
					AllowlistDeprecated: []string{},
					Custom:              []string{},
					Pristine:            Bool(false),
					Denylist:            []string{},
					DenylistDeprecated:  []string{},
				},
				KillSignal:   Signal(DefaultExecKillSignal),
				KillTimeout:  TimeDuration(DefaultExecKillTimeout),
				ReloadSignal: Signal(DefaultExecReloadSignal),
				Splay:        TimeDuration(0 * time.Second),
				Timeout:      TimeDuration(DefaultExecTimeout),
			},
		},
		{
			"with_command",
			&ExecConfig{
				Command: []string{"command"},
			},
			&ExecConfig{
				Command: []string{"command"},
				Enabled: Bool(true),
				Env: &EnvConfig{
					Denylist:            []string{},
					DenylistDeprecated:  []string{},
					Custom:              []string{},
					Pristine:            Bool(false),
					Allowlist:           []string{},
					AllowlistDeprecated: []string{},
				},
				KillSignal:   Signal(DefaultExecKillSignal),
				KillTimeout:  TimeDuration(DefaultExecKillTimeout),
				ReloadSignal: Signal(DefaultExecReloadSignal),
				Splay:        TimeDuration(0 * time.Second),
				Timeout:      TimeDuration(DefaultExecTimeout),
			},
		},
		{
			"with_command_list",
			&ExecConfig{
				Command: []string{"command", "argument1", "argument2"},
			},
			&ExecConfig{
				Command: []string{"command", "argument1", "argument2"},
				Enabled: Bool(true),
				Env: &EnvConfig{
					Denylist:            []string{},
					DenylistDeprecated:  []string{},
					Custom:              []string{},
					Pristine:            Bool(false),
					Allowlist:           []string{},
					AllowlistDeprecated: []string{},
				},
				KillSignal:   Signal(DefaultExecKillSignal),
				KillTimeout:  TimeDuration(DefaultExecKillTimeout),
				ReloadSignal: Signal(DefaultExecReloadSignal),
				Splay:        TimeDuration(0 * time.Second),
				Timeout:      TimeDuration(DefaultExecTimeout),
			},
		},
		{
			"with_shell_command",
			&ExecConfig{
				Command: []string{"command | pipe && command"},
			},
			&ExecConfig{
				Command: []string{"command | pipe && command"},
				Enabled: Bool(true),
				Env: &EnvConfig{
					Denylist:            []string{},
					DenylistDeprecated:  []string{},
					Custom:              []string{},
					Pristine:            Bool(false),
					Allowlist:           []string{},
					AllowlistDeprecated: []string{},
				},
				KillSignal:   Signal(DefaultExecKillSignal),
				KillTimeout:  TimeDuration(DefaultExecKillTimeout),
				ReloadSignal: Signal(DefaultExecReloadSignal),
				Splay:        TimeDuration(0 * time.Second),
				Timeout:      TimeDuration(DefaultExecTimeout),
			},
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			tc.i.Finalize()
			if !reflect.DeepEqual(tc.r, tc.i) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.r, tc.i)
			}
		})
	}
}
