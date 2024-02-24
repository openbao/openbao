// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseAuthConfig(t *testing.T) {
	cases := []struct {
		name string
		s    string
		e    *AuthConfig
		err  bool
	}{
		{
			"empty",
			"",
			nil,
			true,
		},
		{
			"username",
			"username",
			&AuthConfig{
				Username: String("username"),
			},
			false,
		},
		{
			"username_password",
			"username:password",
			&AuthConfig{
				Username: String("username"),
				Password: String("password"),
			},
			false,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			a, err := ParseAuthConfig(tc.s)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.e, a) {
				t.Errorf("\nexp: %#v\nact: %#v", tc.e, a)
			}
		})
	}
}

func TestAuthConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *AuthConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&AuthConfig{},
		},
		{
			"copy",
			&AuthConfig{
				Enabled:  Bool(true),
				Username: String("username"),
				Password: String("password"),
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

func TestAuthConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *AuthConfig
		b    *AuthConfig
		r    *AuthConfig
	}{
		{
			"nil_a",
			nil,
			&AuthConfig{},
			&AuthConfig{},
		},
		{
			"nil_b",
			&AuthConfig{},
			nil,
			&AuthConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&AuthConfig{},
			&AuthConfig{},
			&AuthConfig{},
		},
		{
			"enabled_overrides",
			&AuthConfig{Enabled: Bool(true)},
			&AuthConfig{Enabled: Bool(false)},
			&AuthConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&AuthConfig{Enabled: Bool(true)},
			&AuthConfig{},
			&AuthConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&AuthConfig{},
			&AuthConfig{Enabled: Bool(true)},
			&AuthConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&AuthConfig{Enabled: Bool(true)},
			&AuthConfig{Enabled: Bool(true)},
			&AuthConfig{Enabled: Bool(true)},
		},
		{
			"username_overrides",
			&AuthConfig{Username: String("username")},
			&AuthConfig{Username: String("")},
			&AuthConfig{Username: String("")},
		},
		{
			"username_empty_one",
			&AuthConfig{Username: String("username")},
			&AuthConfig{},
			&AuthConfig{Username: String("username")},
		},
		{
			"username_empty_two",
			&AuthConfig{},
			&AuthConfig{Username: String("username")},
			&AuthConfig{Username: String("username")},
		},
		{
			"username_same",
			&AuthConfig{Username: String("username")},
			&AuthConfig{Username: String("username")},
			&AuthConfig{Username: String("username")},
		},
		{
			"password_overrides",
			&AuthConfig{Password: String("password")},
			&AuthConfig{Password: String("")},
			&AuthConfig{Password: String("")},
		},
		{
			"password_empty_one",
			&AuthConfig{Password: String("password")},
			&AuthConfig{},
			&AuthConfig{Password: String("password")},
		},
		{
			"password_empty_two",
			&AuthConfig{},
			&AuthConfig{Password: String("password")},
			&AuthConfig{Password: String("password")},
		},
		{
			"password_same",
			&AuthConfig{Password: String("password")},
			&AuthConfig{Password: String("password")},
			&AuthConfig{Password: String("password")},
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

func TestAuthConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *AuthConfig
		r    *AuthConfig
	}{
		{
			"empty",
			&AuthConfig{},
			&AuthConfig{
				Enabled:  Bool(false),
				Username: String(""),
				Password: String(""),
			},
		},
		{
			"with_username",
			&AuthConfig{
				Username: String("username"),
			},
			&AuthConfig{
				Enabled:  Bool(true),
				Username: String("username"),
				Password: String(""),
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

func TestAuthConfig_String(t *testing.T) {
	cases := []struct {
		name string
		a    *AuthConfig
		r    string
	}{
		{
			"empty",
			&AuthConfig{
				Enabled: Bool(true),
			},
			"",
		},
		{
			"username",
			&AuthConfig{
				Enabled:  Bool(true),
				Username: String("username"),
			},
			"username",
		},
		{
			"username_password",
			&AuthConfig{
				Enabled:  Bool(true),
				Username: String("username"),
				Password: String("password"),
			},
			"username:password",
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", i, tc.name), func(t *testing.T) {
			result := tc.a.String()
			if tc.r != result {
				t.Errorf("\nexp: %#v\nact: %#v", tc.r, result)
			}
		})
	}
}
