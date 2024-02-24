// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestConsulConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *ConsulConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&ConsulConfig{},
		},
		{
			"same_enabled",
			&ConsulConfig{
				Address:   String("1.2.3.4"),
				Namespace: String("foo"),
				Auth:      &AuthConfig{Enabled: Bool(true)},
				Retry:     &RetryConfig{Enabled: Bool(true)},
				SSL:       &SSLConfig{Enabled: Bool(true)},
				Token:     String("abcd1234"),
				TokenFile: String("/a/very/secret/path"),
				Transport: &TransportConfig{
					DialKeepAlive: TimeDuration(20 * time.Second),
				},
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

func TestConsulConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *ConsulConfig
		b    *ConsulConfig
		r    *ConsulConfig
	}{
		{
			"nil_a",
			nil,
			&ConsulConfig{},
			&ConsulConfig{},
		},
		{
			"nil_b",
			&ConsulConfig{},
			nil,
			&ConsulConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&ConsulConfig{},
			&ConsulConfig{},
			&ConsulConfig{},
		},
		{
			"address_overrides",
			&ConsulConfig{Address: String("same")},
			&ConsulConfig{Address: String("different")},
			&ConsulConfig{Address: String("different")},
		},
		{
			"address_empty_one",
			&ConsulConfig{Address: String("same")},
			&ConsulConfig{},
			&ConsulConfig{Address: String("same")},
		},
		{
			"address_empty_two",
			&ConsulConfig{},
			&ConsulConfig{Address: String("same")},
			&ConsulConfig{Address: String("same")},
		},
		{
			"address_same",
			&ConsulConfig{Address: String("same")},
			&ConsulConfig{Address: String("same")},
			&ConsulConfig{Address: String("same")},
		},
		{
			"namespace_overrides",
			&ConsulConfig{Namespace: String("foo")},
			&ConsulConfig{Namespace: String("bar")},
			&ConsulConfig{Namespace: String("bar")},
		},
		{
			"namespace_empty_one",
			&ConsulConfig{Namespace: String("foo")},
			&ConsulConfig{},
			&ConsulConfig{Namespace: String("foo")},
		},
		{
			"namespace_empty_two",
			&ConsulConfig{},
			&ConsulConfig{Namespace: String("bar")},
			&ConsulConfig{Namespace: String("bar")},
		},
		{
			"namespace_same",
			&ConsulConfig{Namespace: String("foo")},
			&ConsulConfig{Namespace: String("foo")},
			&ConsulConfig{Namespace: String("foo")},
		},
		{
			"auth_overrides",
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(false)}},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(false)}},
		},
		{
			"auth_empty_one",
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
			&ConsulConfig{},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
		},
		{
			"auth_empty_two",
			&ConsulConfig{},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
		},
		{
			"auth_same",
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
			&ConsulConfig{Auth: &AuthConfig{Enabled: Bool(true)}},
		},
		{
			"retry_overrides",
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(false)}},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(false)}},
		},
		{
			"retry_empty_one",
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
			&ConsulConfig{},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
		},
		{
			"retry_empty_two",
			&ConsulConfig{},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
		},
		{
			"retry_same",
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
			&ConsulConfig{Retry: &RetryConfig{Enabled: Bool(true)}},
		},
		{
			"ssl_overrides",
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(false)}},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(false)}},
		},
		{
			"ssl_empty_one",
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
			&ConsulConfig{},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
		},
		{
			"ssl_empty_two",
			&ConsulConfig{},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
		},
		{
			"ssl_same",
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
			&ConsulConfig{SSL: &SSLConfig{Enabled: Bool(true)}},
		},
		{
			"token_overrides",
			&ConsulConfig{Token: String("same")},
			&ConsulConfig{Token: String("different")},
			&ConsulConfig{Token: String("different")},
		},
		{
			"token_empty_one",
			&ConsulConfig{Token: String("same")},
			&ConsulConfig{},
			&ConsulConfig{Token: String("same")},
		},
		{
			"token_empty_two",
			&ConsulConfig{},
			&ConsulConfig{Token: String("same")},
			&ConsulConfig{Token: String("same")},
		},
		{
			"token_same",
			&ConsulConfig{Token: String("same")},
			&ConsulConfig{Token: String("same")},
			&ConsulConfig{Token: String("same")},
		},
		{
			"token_file_overrides",
			&ConsulConfig{TokenFile: String("same")},
			&ConsulConfig{TokenFile: String("different")},
			&ConsulConfig{TokenFile: String("different")},
		},
		{
			"token_file_empty_one",
			&ConsulConfig{TokenFile: String("same")},
			&ConsulConfig{},
			&ConsulConfig{TokenFile: String("same")},
		},
		{
			"token_file_empty_two",
			&ConsulConfig{},
			&ConsulConfig{TokenFile: String("same")},
			&ConsulConfig{TokenFile: String("same")},
		},
		{
			"token_file_same",
			&ConsulConfig{TokenFile: String("same")},
			&ConsulConfig{TokenFile: String("same")},
			&ConsulConfig{TokenFile: String("same")},
		},
		{
			"transport_overrides",
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(20 * time.Second)}},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(20 * time.Second)}},
		},
		{
			"transport_empty_one",
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
			&ConsulConfig{},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
		},
		{
			"transport_empty_two",
			&ConsulConfig{},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
		},
		{
			"transport_same",
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
			&ConsulConfig{Transport: &TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)}},
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

func TestConsulConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *ConsulConfig
		r    *ConsulConfig
	}{
		{
			"empty",
			&ConsulConfig{},
			&ConsulConfig{
				Address:   String(""),
				Namespace: String(""),
				Auth: &AuthConfig{
					Enabled:  Bool(false),
					Username: String(""),
					Password: String(""),
				},
				Retry: &RetryConfig{
					Backoff:    TimeDuration(DefaultRetryBackoff),
					MaxBackoff: TimeDuration(DefaultRetryMaxBackoff),
					Enabled:    Bool(true),
					Attempts:   Int(DefaultRetryAttempts),
				},
				SSL: &SSLConfig{
					CaCert:      String(""),
					CaCertBytes: String(""),
					CaPath:      String(""),
					Cert:        String(""),
					Enabled:     Bool(false),
					Key:         String(""),
					ServerName:  String(""),
					Verify:      Bool(true),
				},
				Token:     String(""),
				TokenFile: String(""),
				Transport: &TransportConfig{
					DialKeepAlive:       TimeDuration(DefaultDialKeepAlive),
					DialTimeout:         TimeDuration(DefaultDialTimeout),
					DisableKeepAlives:   Bool(false),
					IdleConnTimeout:     TimeDuration(DefaultIdleConnTimeout),
					MaxIdleConns:        Int(DefaultMaxIdleConns),
					MaxIdleConnsPerHost: Int(DefaultMaxIdleConnsPerHost),
					TLSHandshakeTimeout: TimeDuration(DefaultTLSHandshakeTimeout),
				},
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
