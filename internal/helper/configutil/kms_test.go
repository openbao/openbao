// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCheckSeals tests the validation of the parsed seal configurations.
func TestCheckSeals(t *testing.T) {
	tt := map[string]struct {
		seals     []*KMS
		wantSeals []*KMS
		wantErr   error
	}{
		"empty": {
			seals:     []*KMS{},
			wantSeals: []*KMS{},
		},
		"single shamir": {
			seals: []*KMS{
				{Type: "shamir"},
			},
			wantSeals: []*KMS{
				{Type: "shamir"},
			},
		},
		"single auto named": {
			seals: []*KMS{
				{Type: "transit"},
			},
			wantSeals: []*KMS{
				{Type: "transit"},
			},
		},
		"single disabled": {
			seals: []*KMS{
				{Type: "transit", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "transit", Disabled: true},
			},
		},
		"two disabled": {
			seals: []*KMS{
				{Type: "transit", Disabled: true},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one disabled seal found"),
		},
		"migration auto to auto": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "pkcs11", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11"},
				{Type: "pkcs11", Disabled: true},
			},
		},
		"migration shamir to shamir": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "shamir", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "shamir"},
				{Type: "shamir", Disabled: true},
			},
		},
		"migration auto to shamir": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "pkcs11", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "shamir"},
				{Type: "pkcs11", Disabled: true},
			},
		},
		"migration shamir to auto": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
			},
		},
		"two auto seals": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "pkcs11"},
			},
			wantErr: errors.New("seals: more than one primary (auto-seal) seal found"),
		},
		"two shamir seals": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "shamir"},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"migration auto-auto with emergency": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "transit", Disabled: true},
				{Type: "shamir"},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11"},
				{Type: "transit", Disabled: true},
				{Type: "shamir"},
			},
		},
		"migration shamir-shamir with emergency": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir"},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"migration auto-shamir with emergency": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "pkcs11", Disabled: true},
				{Type: "shamir"},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"migration shamir-auto with emergency": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir"},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir"},
			},
		},
		"three seals with two disabled": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one disabled seal found"),
		},
		"three seals with two auto seals": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one primary (auto-seal) seal found"),
		},
		"three seals with two shamirs": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "shamir"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"four seals": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir"},
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than three seals declared"),
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			err := CheckSeals(tc.seals)
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.Equal(t, tc.wantSeals, tc.seals)
			} else {
				require.EqualError(t, err, tc.wantErr.Error())
			}
		})
	}
}
