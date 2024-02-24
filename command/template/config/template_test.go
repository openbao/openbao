// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
	"text/template"
	"time"
)

func TestTemplateConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *TemplateConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&TemplateConfig{},
		},
		{
			"same_enabled",
			&TemplateConfig{
				Backup:                   Bool(true),
				Command:                  []string{"command"},
				CommandTimeout:           TimeDuration(10 * time.Second),
				Contents:                 String("contents"),
				CreateDestDirs:           Bool(true),
				Destination:              String("destination"),
				Exec:                     &ExecConfig{Command: []string{"command"}},
				Perms:                    FileMode(0o600),
				Source:                   String("source"),
				Wait:                     &WaitConfig{Min: TimeDuration(10)},
				LeftDelim:                String("left_delim"),
				RightDelim:               String("right_delim"),
				MapToEnvironmentVariable: String(""),
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

func TestTemplateConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *TemplateConfig
		b    *TemplateConfig
		r    *TemplateConfig
	}{
		{
			"nil_a",
			nil,
			&TemplateConfig{},
			&TemplateConfig{},
		},
		{
			"nil_b",
			&TemplateConfig{},
			nil,
			&TemplateConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&TemplateConfig{},
			&TemplateConfig{},
			&TemplateConfig{},
		},
		{
			"backup_overrides",
			&TemplateConfig{Backup: Bool(true)},
			&TemplateConfig{Backup: Bool(false)},
			&TemplateConfig{Backup: Bool(false)},
		},
		{
			"backup_empty_one",
			&TemplateConfig{Backup: Bool(true)},
			&TemplateConfig{},
			&TemplateConfig{Backup: Bool(true)},
		},
		{
			"backup_empty_two",
			&TemplateConfig{},
			&TemplateConfig{Backup: Bool(true)},
			&TemplateConfig{Backup: Bool(true)},
		},
		{
			"backup_same",
			&TemplateConfig{Backup: Bool(true)},
			&TemplateConfig{Backup: Bool(true)},
			&TemplateConfig{Backup: Bool(true)},
		},
		{
			"command_overrides",
			&TemplateConfig{Command: []string{"command"}},
			&TemplateConfig{Command: []string{}},
			&TemplateConfig{Command: []string{}},
		},
		{
			"command_empty_one",
			&TemplateConfig{Command: []string{"command"}},
			&TemplateConfig{},
			&TemplateConfig{Command: []string{"command"}},
		},
		{
			"command_empty_two",
			&TemplateConfig{},
			&TemplateConfig{Command: []string{"command"}},
			&TemplateConfig{Command: []string{"command"}},
		},
		{
			"command_same",
			&TemplateConfig{Command: []string{"command"}},
			&TemplateConfig{Command: []string{"command"}},
			&TemplateConfig{Command: []string{"command"}},
		},
		{
			"command_timeout_overrides",
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
			&TemplateConfig{CommandTimeout: TimeDuration(0 * time.Second)},
			&TemplateConfig{CommandTimeout: TimeDuration(0 * time.Second)},
		},
		{
			"command_timeout_empty_one",
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
			&TemplateConfig{},
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"command_timeout_empty_two",
			&TemplateConfig{},
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"command_timeout_same",
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
			&TemplateConfig{CommandTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"contents_overrides",
			&TemplateConfig{Contents: String("contents")},
			&TemplateConfig{Contents: String("")},
			&TemplateConfig{Contents: String("")},
		},
		{
			"contents_empty_one",
			&TemplateConfig{Contents: String("contents")},
			&TemplateConfig{},
			&TemplateConfig{Contents: String("contents")},
		},
		{
			"contents_empty_two",
			&TemplateConfig{},
			&TemplateConfig{Contents: String("contents")},
			&TemplateConfig{Contents: String("contents")},
		},
		{
			"contents_same",
			&TemplateConfig{Contents: String("contents")},
			&TemplateConfig{Contents: String("contents")},
			&TemplateConfig{Contents: String("contents")},
		},
		{
			"create_dest_dirs_overrides",
			&TemplateConfig{CreateDestDirs: Bool(false)},
			&TemplateConfig{CreateDestDirs: Bool(true)},
			&TemplateConfig{CreateDestDirs: Bool(true)},
		},
		{
			"create_dest_dirs_empty_one",
			&TemplateConfig{CreateDestDirs: Bool(false)},
			&TemplateConfig{},
			&TemplateConfig{CreateDestDirs: Bool(false)},
		},
		{
			"create_dest_dirs_empty_two",
			&TemplateConfig{},
			&TemplateConfig{CreateDestDirs: Bool(false)},
			&TemplateConfig{CreateDestDirs: Bool(false)},
		},
		{
			"create_dest_dirs_same",
			&TemplateConfig{CreateDestDirs: Bool(false)},
			&TemplateConfig{CreateDestDirs: Bool(false)},
			&TemplateConfig{CreateDestDirs: Bool(false)},
		},
		{
			"destination_overrides",
			&TemplateConfig{Destination: String("destination")},
			&TemplateConfig{Destination: String("")},
			&TemplateConfig{Destination: String("")},
		},
		{
			"destination_empty_one",
			&TemplateConfig{Destination: String("destination")},
			&TemplateConfig{},
			&TemplateConfig{Destination: String("destination")},
		},
		{
			"destination_empty_two",
			&TemplateConfig{},
			&TemplateConfig{Destination: String("destination")},
			&TemplateConfig{Destination: String("destination")},
		},
		{
			"destination_same",
			&TemplateConfig{Destination: String("destination")},
			&TemplateConfig{Destination: String("destination")},
			&TemplateConfig{Destination: String("destination")},
		},
		{
			"err_missing_key_overrides",
			&TemplateConfig{ErrMissingKey: Bool(true)},
			&TemplateConfig{ErrMissingKey: Bool(false)},
			&TemplateConfig{ErrMissingKey: Bool(false)},
		},
		{
			"err_missing_key_empty_one",
			&TemplateConfig{ErrMissingKey: Bool(true)},
			&TemplateConfig{},
			&TemplateConfig{ErrMissingKey: Bool(true)},
		},
		{
			"err_missing_key_empty_two",
			&TemplateConfig{},
			&TemplateConfig{ErrMissingKey: Bool(true)},
			&TemplateConfig{ErrMissingKey: Bool(true)},
		},
		{
			"err_missing_key_same",
			&TemplateConfig{ErrMissingKey: Bool(true)},
			&TemplateConfig{ErrMissingKey: Bool(true)},
			&TemplateConfig{ErrMissingKey: Bool(true)},
		},
		{
			"exec_overrides",
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{}}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{}}},
		},
		{
			"exec_empty_one",
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
			&TemplateConfig{Exec: &ExecConfig{}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
		},
		{
			"exec_empty_two",
			&TemplateConfig{Exec: &ExecConfig{}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
		},
		{
			"exec_same",
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
			&TemplateConfig{Exec: &ExecConfig{Command: []string{"command"}}},
		},
		{
			"perms_overrides",
			&TemplateConfig{Perms: FileMode(0o600)},
			&TemplateConfig{Perms: FileMode(0o000)},
			&TemplateConfig{Perms: FileMode(0o000)},
		},
		{
			"perms_empty_one",
			&TemplateConfig{Perms: FileMode(0o600)},
			&TemplateConfig{},
			&TemplateConfig{Perms: FileMode(0o600)},
		},
		{
			"perms_empty_two",
			&TemplateConfig{},
			&TemplateConfig{Perms: FileMode(0o600)},
			&TemplateConfig{Perms: FileMode(0o600)},
		},
		{
			"perms_same",
			&TemplateConfig{Perms: FileMode(0o600)},
			&TemplateConfig{Perms: FileMode(0o600)},
			&TemplateConfig{Perms: FileMode(0o600)},
		},
		{
			"source_overrides",
			&TemplateConfig{Source: String("source")},
			&TemplateConfig{Source: String("")},
			&TemplateConfig{Source: String("")},
		},
		{
			"source_empty_one",
			&TemplateConfig{Source: String("source")},
			&TemplateConfig{},
			&TemplateConfig{Source: String("source")},
		},
		{
			"source_empty_two",
			&TemplateConfig{},
			&TemplateConfig{Source: String("source")},
			&TemplateConfig{Source: String("source")},
		},
		{
			"source_same",
			&TemplateConfig{Source: String("source")},
			&TemplateConfig{Source: String("source")},
			&TemplateConfig{Source: String("source")},
		},
		{
			"wait_overrides",
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(0)}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(0)}},
		},
		{
			"wait_empty_one",
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
			&TemplateConfig{Wait: &WaitConfig{}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
		},
		{
			"wait_empty_two",
			&TemplateConfig{Wait: &WaitConfig{}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
		},
		{
			"wait_same",
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
			&TemplateConfig{Wait: &WaitConfig{Min: TimeDuration(10)}},
		},
		{
			"left_delim_overrides",
			&TemplateConfig{LeftDelim: String("left_delim")},
			&TemplateConfig{LeftDelim: String("")},
			&TemplateConfig{LeftDelim: String("")},
		},
		{
			"left_delim_empty_one",
			&TemplateConfig{LeftDelim: String("left_delim")},
			&TemplateConfig{},
			&TemplateConfig{LeftDelim: String("left_delim")},
		},
		{
			"left_delim_empty_two",
			&TemplateConfig{},
			&TemplateConfig{LeftDelim: String("left_delim")},
			&TemplateConfig{LeftDelim: String("left_delim")},
		},
		{
			"left_delim_same",
			&TemplateConfig{LeftDelim: String("left_delim")},
			&TemplateConfig{LeftDelim: String("left_delim")},
			&TemplateConfig{LeftDelim: String("left_delim")},
		},
		{
			"right_delim_overrides",
			&TemplateConfig{RightDelim: String("right_delim")},
			&TemplateConfig{RightDelim: String("")},
			&TemplateConfig{RightDelim: String("")},
		},
		{
			"right_delim_empty_one",
			&TemplateConfig{RightDelim: String("right_delim")},
			&TemplateConfig{},
			&TemplateConfig{RightDelim: String("right_delim")},
		},
		{
			"right_delim_empty_two",
			&TemplateConfig{},
			&TemplateConfig{RightDelim: String("right_delim")},
			&TemplateConfig{RightDelim: String("right_delim")},
		},
		{
			"right_delim_same",
			&TemplateConfig{RightDelim: String("right_delim")},
			&TemplateConfig{RightDelim: String("right_delim")},
			&TemplateConfig{RightDelim: String("right_delim")},
		},
		{
			"map_to_env_var_empty_one",
			&TemplateConfig{MapToEnvironmentVariable: String("FOO")},
			&TemplateConfig{},
			&TemplateConfig{MapToEnvironmentVariable: String("FOO")},
		},
		{
			"map_to_env_var_empty_two",
			&TemplateConfig{},
			&TemplateConfig{MapToEnvironmentVariable: String("FOO")},
			&TemplateConfig{MapToEnvironmentVariable: String("FOO")},
		},
		{
			"map_to_env_var_override",
			&TemplateConfig{MapToEnvironmentVariable: String("FOO")},
			&TemplateConfig{MapToEnvironmentVariable: String("BAR")},
			&TemplateConfig{MapToEnvironmentVariable: String("BAR")},
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

func TestTemplateConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *TemplateConfig
		r    *TemplateConfig
	}{
		{
			"empty",
			&TemplateConfig{},
			&TemplateConfig{
				Backup:         Bool(false),
				Command:        []string{},
				CommandTimeout: TimeDuration(DefaultTemplateCommandTimeout),
				Contents:       String(""),
				CreateDestDirs: Bool(true),
				Destination:    String(""),
				ErrMissingKey:  Bool(false),
				ErrFatal:       Bool(true),
				Exec: &ExecConfig{
					Command: []string{},
					Enabled: Bool(false),
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
					Timeout:      TimeDuration(DefaultTemplateCommandTimeout),
				},
				Perms:  FileMode(0),
				Source: String(""),
				Wait: &WaitConfig{
					Enabled: Bool(false),
					Max:     TimeDuration(0 * time.Second),
					Min:     TimeDuration(0 * time.Second),
				},
				LeftDelim:                  String(""),
				RightDelim:                 String(""),
				ExtFuncMap:                 template.FuncMap{},
				FunctionDenylist:           []string{},
				FunctionDenylistDeprecated: []string{},
				SandboxPath:                String(""),
				MapToEnvironmentVariable:   String(""),
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

func TestTemplateConfig_Display(t *testing.T) {
	cases := []struct {
		name string
		c    *TemplateConfig
		e    string
	}{
		{
			"nil",
			nil,
			"",
		},
		{
			"with_source",
			&TemplateConfig{
				Source: String("/var/my.tpl"),
			},
			`"/var/my.tpl" => ""`,
		},
		{
			"with_contents",
			&TemplateConfig{
				Contents: String("hello"),
			},
			`"(dynamic)" => ""`,
		},
		{
			"with_destination",
			&TemplateConfig{
				Source:      String("/var/my.tpl"),
				Destination: String("/var/my.txt"),
			},
			`"/var/my.tpl" => "/var/my.txt"`,
		},
		{
			"with_environment_variable",
			&TemplateConfig{
				MapToEnvironmentVariable: String("FOO"),
			},
			`"" => "FOO"`,
		},
		{
			"with_environment_variable_and_contents",
			&TemplateConfig{
				MapToEnvironmentVariable: String("FOO"),
				Contents:                 String("hello"),
			},
			`"(dynamic)" => "FOO"`,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a := tc.c.Display()
			if tc.e != a {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, a)
			}
		})
	}
}

func TestParseTemplateConfig(t *testing.T) {
	cases := []struct {
		name string
		i    string
		e    *TemplateConfig
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"empty_with_spaces",
			" ",
			nil,
			true,
		},
		{
			"default",
			"/tmp/a.txt:/tmp/b.txt:command",
			&TemplateConfig{
				Source:      String("/tmp/a.txt"),
				Destination: String("/tmp/b.txt"),
				Command:     []string{"command"},
			},
			false,
		},
		{
			"single",
			"/tmp/a.txt",
			&TemplateConfig{
				Source: String("/tmp/a.txt"),
			},
			false,
		},
		{
			"single_windows_drive",
			`z:\foo`,
			&TemplateConfig{
				Source: String(`z:\foo`),
			},
			false,
		},
		{
			"windows_drives",
			`C:\abc\123:D:\xyz\789:command`,
			&TemplateConfig{
				Source:      String(`C:\abc\123`),
				Destination: String(`D:\xyz\789`),
				Command:     []string{`command`},
			},
			false,
		},
		{
			"windows_drives_with_colon",
			`C:\abc\123:D:\xyz\789:sub:command`,
			&TemplateConfig{
				Source:      String(`C:\abc\123`),
				Destination: String(`D:\xyz\789`),
				Command:     []string{`sub:command`},
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			c, err := ParseTemplateConfig(tc.i)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.e, c) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, c)
			}
		})
	}
}
