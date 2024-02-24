// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestTransportConfig_Copy(t *testing.T) {
	cases := []struct {
		name string
		a    *TransportConfig
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&TransportConfig{},
		},
		{
			"same_enabled",
			&TransportConfig{
				DialKeepAlive:       TimeDuration(10 * time.Second),
				DialTimeout:         TimeDuration(20 * time.Second),
				DisableKeepAlives:   Bool(true),
				IdleConnTimeout:     TimeDuration(40 * time.Second),
				MaxIdleConns:        Int(150),
				MaxIdleConnsPerHost: Int(15),
				TLSHandshakeTimeout: TimeDuration(30 * time.Second),
			},
		},
		{
			"same_enabled_custom_dialer",
			&TransportConfig{
				CustomDialer:        &net.Dialer{Timeout: 10 * time.Second},
				DisableKeepAlives:   Bool(true),
				IdleConnTimeout:     TimeDuration(40 * time.Second),
				MaxIdleConns:        Int(150),
				MaxIdleConnsPerHost: Int(15),
				TLSHandshakeTimeout: TimeDuration(30 * time.Second),
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

func TestTransportConfig_Merge(t *testing.T) {
	cases := []struct {
		name string
		a    *TransportConfig
		b    *TransportConfig
		r    *TransportConfig
	}{
		{
			"nil_a",
			nil,
			&TransportConfig{},
			&TransportConfig{},
		},
		{
			"nil_b",
			&TransportConfig{},
			nil,
			&TransportConfig{},
		},
		{
			"nil_both",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			&TransportConfig{},
			&TransportConfig{},
			&TransportConfig{},
		},
		{
			"dial_keep_alive_overrides",
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
			&TransportConfig{DialKeepAlive: TimeDuration(20 * time.Second)},
			&TransportConfig{DialKeepAlive: TimeDuration(20 * time.Second)},
		},
		{
			"dial_keep_alive_empty_one",
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
			&TransportConfig{},
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
		},
		{
			"dial_keep_alive_empty_two",
			&TransportConfig{},
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
		},
		{
			"dial_keep_alive_same",
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
			&TransportConfig{DialKeepAlive: TimeDuration(10 * time.Second)},
		},
		{
			"dial_timeout_overrides",
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{DialTimeout: TimeDuration(20 * time.Second)},
			&TransportConfig{DialTimeout: TimeDuration(20 * time.Second)},
		},
		{
			"dial_timeout_empty_one",
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{},
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"dial_timeout_empty_two",
			&TransportConfig{},
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"dial_timeout_same",
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{DialTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"disable_keep_alives_overrides",
			&TransportConfig{DisableKeepAlives: Bool(true)},
			&TransportConfig{DisableKeepAlives: Bool(false)},
			&TransportConfig{DisableKeepAlives: Bool(false)},
		},
		{
			"disable_keep_alives_empty_one",
			&TransportConfig{DisableKeepAlives: Bool(true)},
			&TransportConfig{},
			&TransportConfig{DisableKeepAlives: Bool(true)},
		},
		{
			"disable_keep_alives_empty_two",
			&TransportConfig{},
			&TransportConfig{DisableKeepAlives: Bool(true)},
			&TransportConfig{DisableKeepAlives: Bool(true)},
		},
		{
			"disable_keep_alives_same",
			&TransportConfig{DisableKeepAlives: Bool(true)},
			&TransportConfig{DisableKeepAlives: Bool(true)},
			&TransportConfig{DisableKeepAlives: Bool(true)},
		},
		{
			"idle_conn_timeout_overrides",
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
			&TransportConfig{IdleConnTimeout: TimeDuration(250 * time.Second)},
			&TransportConfig{IdleConnTimeout: TimeDuration(250 * time.Second)},
		},
		{
			"idle_conn_timeout_empty_one",
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
			&TransportConfig{},
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
		},
		{
			"idle_conn_timeout_empty_two",
			&TransportConfig{},
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
		},
		{
			"idle_conn_timeout_same",
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
			&TransportConfig{IdleConnTimeout: TimeDuration(150 * time.Second)},
		},
		{
			"max_idle_conns_overrides",
			&TransportConfig{MaxIdleConns: Int(10)},
			&TransportConfig{MaxIdleConns: Int(20)},
			&TransportConfig{MaxIdleConns: Int(20)},
		},
		{
			"max_idle_conns_empty_one",
			&TransportConfig{MaxIdleConns: Int(10)},
			&TransportConfig{},
			&TransportConfig{MaxIdleConns: Int(10)},
		},
		{
			"max_idle_conns_empty_two",
			&TransportConfig{},
			&TransportConfig{MaxIdleConns: Int(10)},
			&TransportConfig{MaxIdleConns: Int(10)},
		},
		{
			"max_idle_conns_same",
			&TransportConfig{MaxIdleConns: Int(10)},
			&TransportConfig{MaxIdleConns: Int(10)},
			&TransportConfig{MaxIdleConns: Int(10)},
		},
		{
			"max_idle_conns_per_host_overrides",
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
			&TransportConfig{MaxIdleConnsPerHost: Int(20)},
			&TransportConfig{MaxIdleConnsPerHost: Int(20)},
		},
		{
			"max_idle_conns_per_host_empty_one",
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
			&TransportConfig{},
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
		},
		{
			"max_idle_conns_per_host_empty_two",
			&TransportConfig{},
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
		},
		{
			"max_idle_conns_per_host_same",
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
			&TransportConfig{MaxIdleConnsPerHost: Int(10)},
		},
		{
			"tls_handshake_timeout_overrides",
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(20 * time.Second)},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(20 * time.Second)},
		},
		{
			"tls_handshake_timeout_empty_one",
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"tls_handshake_timeout_empty_two",
			&TransportConfig{},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"tls_handshake_timeout_same",
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
			&TransportConfig{TLSHandshakeTimeout: TimeDuration(10 * time.Second)},
		},
		{
			"custom_transport_dialer",
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 20 * time.Second}},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 20 * time.Second}},
		},
		{
			"custom_transport_dialer_empty_one",
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
			&TransportConfig{},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
		},
		{
			"custom_transport_dialer_empty_two",
			&TransportConfig{},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
		},
		{
			"custom_transport_dialer_same",
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
			&TransportConfig{CustomDialer: &net.Dialer{Timeout: 10 * time.Second}},
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

func TestTransportConfig_Finalize(t *testing.T) {
	cases := []struct {
		name string
		i    *TransportConfig
		r    *TransportConfig
	}{
		{
			"empty",
			&TransportConfig{},
			&TransportConfig{
				DialKeepAlive:       TimeDuration(DefaultDialKeepAlive),
				DialTimeout:         TimeDuration(DefaultDialTimeout),
				DisableKeepAlives:   Bool(false),
				IdleConnTimeout:     TimeDuration(DefaultIdleConnTimeout),
				MaxIdleConns:        Int(DefaultMaxIdleConns),
				MaxIdleConnsPerHost: Int(DefaultMaxIdleConnsPerHost),
				TLSHandshakeTimeout: TimeDuration(DefaultTLSHandshakeTimeout),
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
