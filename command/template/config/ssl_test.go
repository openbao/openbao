// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSSLConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *SSLConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&SSLConfig{},
		},
		{
			"same_enabled",
			&SSLConfig{
				Enabled:     Bool(true),
				Verify:      Bool(true),
				CaCert:      String("ca_cert"),
				CaCertBytes: String("ca_cert_bytes"),
				CaPath:      String("ca_path"),
				Cert:        String("cert"),
				Key:         String("key"),
				ServerName:  String("server_name"),
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

func TestSSLConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *SSLConfig
		b    *SSLConfig
		r    *SSLConfig
	}{
		{
			"nil_a",
			nil,
			&SSLConfig{},
			&SSLConfig{},
		},
		{
			"nil_b",
			&SSLConfig{},
			nil,
			&SSLConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&SSLConfig{},
			&SSLConfig{},
			&SSLConfig{},
		},
		{
			"enabled_overrides",
			&SSLConfig{Enabled: Bool(true)},
			&SSLConfig{Enabled: Bool(false)},
			&SSLConfig{Enabled: Bool(false)},
		},
		{
			"enabled_empty_one",
			&SSLConfig{Enabled: Bool(true)},
			&SSLConfig{},
			&SSLConfig{Enabled: Bool(true)},
		},
		{
			"enabled_empty_two",
			&SSLConfig{},
			&SSLConfig{Enabled: Bool(true)},
			&SSLConfig{Enabled: Bool(true)},
		},
		{
			"enabled_same",
			&SSLConfig{Enabled: Bool(true)},
			&SSLConfig{Enabled: Bool(true)},
			&SSLConfig{Enabled: Bool(true)},
		},
		{
			"verify_overrides",
			&SSLConfig{Verify: Bool(true)},
			&SSLConfig{Verify: Bool(false)},
			&SSLConfig{Verify: Bool(false)},
		},
		{
			"verify_empty_one",
			&SSLConfig{Verify: Bool(true)},
			&SSLConfig{},
			&SSLConfig{Verify: Bool(true)},
		},
		{
			"verify_empty_two",
			&SSLConfig{},
			&SSLConfig{Verify: Bool(true)},
			&SSLConfig{Verify: Bool(true)},
		},
		{
			"verify_same",
			&SSLConfig{Verify: Bool(true)},
			&SSLConfig{Verify: Bool(true)},
			&SSLConfig{Verify: Bool(true)},
		},
		{
			"cert_overrides",
			&SSLConfig{Cert: String("cert")},
			&SSLConfig{Cert: String("")},
			&SSLConfig{Cert: String("")},
		},
		{
			"cert_empty_one",
			&SSLConfig{Cert: String("cert")},
			&SSLConfig{},
			&SSLConfig{Cert: String("cert")},
		},
		{
			"cert_empty_two",
			&SSLConfig{},
			&SSLConfig{Cert: String("cert")},
			&SSLConfig{Cert: String("cert")},
		},
		{
			"cert_same",
			&SSLConfig{Cert: String("cert")},
			&SSLConfig{Cert: String("cert")},
			&SSLConfig{Cert: String("cert")},
		},
		{
			"key_overrides",
			&SSLConfig{Key: String("key")},
			&SSLConfig{Key: String("")},
			&SSLConfig{Key: String("")},
		},
		{
			"key_empty_one",
			&SSLConfig{Key: String("key")},
			&SSLConfig{},
			&SSLConfig{Key: String("key")},
		},
		{
			"key_empty_two",
			&SSLConfig{},
			&SSLConfig{Key: String("key")},
			&SSLConfig{Key: String("key")},
		},
		{
			"key_same",
			&SSLConfig{Key: String("key")},
			&SSLConfig{Key: String("key")},
			&SSLConfig{Key: String("key")},
		},
		{
			"ca_cert_overrides",
			&SSLConfig{CaCert: String("ca_cert")},
			&SSLConfig{CaCert: String("")},
			&SSLConfig{CaCert: String("")},
		},
		{
			"ca_cert_empty_one",
			&SSLConfig{CaCert: String("ca_cert")},
			&SSLConfig{},
			&SSLConfig{CaCert: String("ca_cert")},
		},
		{
			"ca_cert_empty_two",
			&SSLConfig{},
			&SSLConfig{CaCert: String("ca_cert")},
			&SSLConfig{CaCert: String("ca_cert")},
		},
		{
			"ca_cert_same",
			&SSLConfig{CaCert: String("ca_cert")},
			&SSLConfig{CaCert: String("ca_cert")},
			&SSLConfig{CaCert: String("ca_cert")},
		},
		{
			"ca_cert_bytes_overrides",
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
			&SSLConfig{CaCertBytes: String("")},
			&SSLConfig{CaCertBytes: String("")},
		},
		{
			"ca_cert_bytes_empty_one",
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
			&SSLConfig{},
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
		},
		{
			"ca_cert_bytes_empty_two",
			&SSLConfig{},
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
		},
		{
			"ca_cert_bytes_same",
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
			&SSLConfig{CaCertBytes: String("ca_cert_bytes")},
		},
		{
			"ca_path_overrides",
			&SSLConfig{CaPath: String("ca_path")},
			&SSLConfig{CaPath: String("")},
			&SSLConfig{CaPath: String("")},
		},
		{
			"ca_path_empty_one",
			&SSLConfig{CaPath: String("ca_path")},
			&SSLConfig{},
			&SSLConfig{CaPath: String("ca_path")},
		},
		{
			"ca_path_empty_two",
			&SSLConfig{},
			&SSLConfig{CaPath: String("ca_path")},
			&SSLConfig{CaPath: String("ca_path")},
		},
		{
			"ca_path_same",
			&SSLConfig{CaPath: String("ca_path")},
			&SSLConfig{CaPath: String("ca_path")},
			&SSLConfig{CaPath: String("ca_path")},
		},
		{
			"server_name_overrides",
			&SSLConfig{ServerName: String("server_name")},
			&SSLConfig{ServerName: String("")},
			&SSLConfig{ServerName: String("")},
		},
		{
			"server_name_empty_one",
			&SSLConfig{ServerName: String("server_name")},
			&SSLConfig{},
			&SSLConfig{ServerName: String("server_name")},
		},
		{
			"server_name_empty_two",
			&SSLConfig{},
			&SSLConfig{ServerName: String("server_name")},
			&SSLConfig{ServerName: String("server_name")},
		},
		{
			"server_name_same",
			&SSLConfig{ServerName: String("server_name")},
			&SSLConfig{ServerName: String("server_name")},
			&SSLConfig{ServerName: String("server_name")},
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

func TestSSLConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *SSLConfig
		r    *SSLConfig
	}{
		{
			"empty",
			&SSLConfig{},
			&SSLConfig{
				Enabled:     Bool(false),
				Cert:        String(""),
				CaCert:      String(""),
				CaCertBytes: String(""),
				CaPath:      String(""),
				Key:         String(""),
				ServerName:  String(""),
				Verify:      Bool(true),
			},
		},
		{
			"with_cert",
			&SSLConfig{
				Cert: String("cert"),
			},
			&SSLConfig{
				Enabled:     Bool(true),
				Cert:        String("cert"),
				CaCert:      String(""),
				CaCertBytes: String(""),
				CaPath:      String(""),
				Key:         String(""),
				ServerName:  String(""),
				Verify:      Bool(true),
			},
		},
		{
			"with_ca_cert",
			&SSLConfig{
				CaCert: String("ca_cert"),
			},
			&SSLConfig{
				Enabled:     Bool(true),
				Cert:        String(""),
				CaCert:      String("ca_cert"),
				CaCertBytes: String(""),
				CaPath:      String(""),
				Key:         String(""),
				ServerName:  String(""),
				Verify:      Bool(true),
			},
		},
		{
			"with_ca_cert_bytes",
			&SSLConfig{
				CaCertBytes: String("ca_cert_bytes"),
			},
			&SSLConfig{
				Enabled:     Bool(true),
				Cert:        String(""),
				CaCert:      String(""),
				CaCertBytes: String("ca_cert_bytes"),
				CaPath:      String(""),
				Key:         String(""),
				ServerName:  String(""),
				Verify:      Bool(true),
			},
		},
		{
			"with_ca_path",
			&SSLConfig{
				CaPath: String("ca_path"),
			},
			&SSLConfig{
				Enabled:     Bool(true),
				Cert:        String(""),
				CaCert:      String(""),
				CaCertBytes: String(""),
				CaPath:      String("ca_path"),
				Key:         String(""),
				ServerName:  String(""),
				Verify:      Bool(true),
			},
		},
		{
			"with_key",
			&SSLConfig{
				Key: String("key"),
			},
			&SSLConfig{
				Enabled:     Bool(true),
				Cert:        String(""),
				CaCert:      String(""),
				CaCertBytes: String(""),
				CaPath:      String(""),
				Key:         String("key"),
				ServerName:  String(""),
				Verify:      Bool(true),
			},
		},
		{
			"with_server_name",
			&SSLConfig{
				ServerName: String("server_name"),
			},
			&SSLConfig{
				Enabled:     Bool(true),
				Cert:        String(""),
				CaCert:      String(""),
				CaCertBytes: String(""),
				CaPath:      String(""),
				Key:         String(""),
				ServerName:  String("server_name"),
				Verify:      Bool(true),
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
