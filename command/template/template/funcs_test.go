// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package template

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	dep "github.com/hashicorp/consul-template/dependency"
)

// NOTE: the template functions are all tested in ./template_test.go and
// the tests here are for ancillary code only.

func TestFileSandbox(t *testing.T) {
	// while most of the function can be tested lexigraphically,
	// we need to be able to walk actual symlinks.
	_, filename, _, _ := runtime.Caller(0)
	sandboxDir := filepath.Join(filepath.Dir(filename), "testdata", "sandbox")
	cases := []struct {
		name     string
		sandbox  string
		path     string
		expected error
	}{
		{
			"absolute_path_no_sandbox",
			"",
			"/path/to/file",
			nil,
		},
		{
			"relative_path_no_sandbox",
			"",
			"./path/to/file",
			nil,
		},
		{
			"absolute_path_with_sandbox",
			sandboxDir,
			filepath.Join(sandboxDir, "path/to/file"),
			nil,
		},
		{
			"relative_path_in_sandbox",
			sandboxDir,
			filepath.Join(sandboxDir, "path/to/../to/file"),
			nil,
		},
		{
			"symlink_path_in_sandbox",
			sandboxDir,
			filepath.Join(sandboxDir, "path/to/ok-symlink"),
			nil,
		},
		{
			"relative_path_escaping_sandbox",
			sandboxDir,
			filepath.Join(sandboxDir, "path/../../../funcs_test.go"),
			fmt.Errorf("'%s' is outside of sandbox",
				filepath.Join(sandboxDir, "path/../../../funcs_test.go")),
		},
		{
			"symlink_escaping_sandbox",
			sandboxDir,
			filepath.Join(sandboxDir, "path/to/bad-symlink"),
			fmt.Errorf("'%s' is outside of sandbox",
				filepath.Join(sandboxDir, "path/to/bad-symlink")),
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			err := pathInSandbox(tc.sandbox, tc.path)
			if err != nil && tc.expected != nil {
				if err.Error() != tc.expected.Error() {
					t.Fatalf("expected %v got %v", tc.expected, err)
				}
			} else if err != tc.expected {
				t.Fatalf("expected %v got %v", tc.expected, err)
			}
		})
	}
}

func Test_byMeta(t *testing.T) {
	svcA := &dep.HealthService{
		ServiceMeta: map[string]string{
			"version":         "v2",
			"version_num":     "2",
			"bad_version_num": "1zz",
			"env":             "dev",
		},
		ID: "svcA",
	}

	svcB := &dep.HealthService{
		ServiceMeta: map[string]string{
			"version":         "v11",
			"version_num":     "11",
			"bad_version_num": "1zz",
			"env":             "prod",
		},
		ID: "svcB",
	}

	svcC := &dep.HealthService{
		ServiceMeta: map[string]string{
			"version":         "v11",
			"version_num":     "11",
			"bad_version_num": "1zz",
			"env":             "prod",
		},
		ID: "svcC",
	}

	type args struct {
		meta     string
		services []*dep.HealthService
	}

	tests := []struct {
		name       string
		args       args
		wantGroups map[string][]*dep.HealthService
		wantErr    bool
	}{
		{
			name: "version string",
			args: args{
				meta:     "version",
				services: []*dep.HealthService{svcA, svcB, svcC},
			},
			wantGroups: map[string][]*dep.HealthService{
				"v11": {svcB, svcC},
				"v2":  {svcA},
			},
			wantErr: false,
		},
		{
			name: "version number",
			args: args{
				meta:     "version_num|int",
				services: []*dep.HealthService{svcA, svcB, svcC},
			},
			wantGroups: map[string][]*dep.HealthService{
				"00011": {svcB, svcC},
				"00002": {svcA},
			},
			wantErr: false,
		},
		{
			name: "bad version number",
			args: args{
				meta:     "bad_version_num|int",
				services: []*dep.HealthService{svcA, svcB, svcC},
			},
			wantGroups: nil,
			wantErr:    true,
		},
		{
			name: "multiple meta",
			args: args{
				meta:     "env,version_num|int,version",
				services: []*dep.HealthService{svcA, svcB, svcC},
			},
			wantGroups: map[string][]*dep.HealthService{
				"dev_00002_v2":   {svcA},
				"prod_00011_v11": {svcB, svcC},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGroups, err := byMeta(tt.args.meta, tt.args.services)
			if (err != nil) != tt.wantErr {
				t.Errorf("byMeta() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			onlyIDs := func(groups map[string][]*dep.HealthService) (ids map[string]map[string]int) {
				ids = make(map[string]map[string]int)
				for group, svcs := range groups {
					ids[group] = make(map[string]int)
					for _, svc := range svcs {
						ids[group][svc.ID] = 1
					}
				}
				return
			}

			gotIDs := onlyIDs(gotGroups)
			wantIDs := onlyIDs(tt.wantGroups)
			if !reflect.DeepEqual(gotGroups, tt.wantGroups) {
				t.Errorf("byMeta() = %v, want %v", gotIDs, wantIDs)
			}
		})
	}
}

func Test_sha256Hex(t *testing.T) {
	type args struct {
		item string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Should return the proper string",
			args: args{
				item: "bladibla",
			},
			want:    "54cf4c66bcabb5c20e25331c01dd600b73369e97a947861bd8d3a0e0b8b3d70b",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sha256Hex(tt.args.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("sha256Hex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sha256Hex() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_md5sum(t *testing.T) {
	type args struct {
		item string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Should return the proper string",
			args: args{
				item: "bladibla",
			},
			want:    "c6886abd136f7daece35aebb01f1b713",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := md5sum(tt.args.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("md5sum() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("md5sum() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hmacSHA256Hex(t *testing.T) {
	type args struct {
		message string
		key     string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Should return the proper string",
			args: args{
				message: "bladibla",
				key:     "foobar",
			},
			want:    "82cd4c36fa45a1936e93d005ea2fd008350339bb9246a3ba0c8dfecb9d77155b",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hmacSHA256Hex(tt.args.message, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("hmacSHA256Hex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("hmacSHA256Hex() got = %v, want %v", got, tt.want)
			}
		})
	}
}
