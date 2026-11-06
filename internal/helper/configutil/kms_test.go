// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCheckAndResolveSeals tests the validation and resolution
// of the parsed seal configurations.
func TestCheckAndResolveSeals(t *testing.T) {
	tt := map[string]struct {
		seals     []*KMS
		wantSeals []*KMS
		wantErr   error
	}{
		"empty": {
			seals:     []*KMS{},
			wantSeals: []*KMS{},
		},
		"single shamir unnamed": {
			seals: []*KMS{
				{Type: "shamir"},
			},
			wantSeals: []*KMS{
				{Type: "shamir", Name: "default"},
			},
		},
		"single auto named": {
			seals: []*KMS{
				{Type: "transit"},
			},
			wantSeals: []*KMS{
				{Type: "transit", Name: "default"},
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
				{Type: "pkcs11", Name: "default"},
				{Type: "pkcs11", Name: "default", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "pkcs11", Name: "default", Disabled: true},
			},
		},
		"migration shamir to shamir": {
			seals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "shamir", Name: "default", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "shamir", Name: "default", Disabled: true},
			},
		},
		"migration auto to shamir": {
			seals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "pkcs11", Name: "default", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "pkcs11", Name: "default", Disabled: true},
			},
		},
		"migration shamir to auto": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: "default", Disabled: true},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: "default", Disabled: true},
			},
		},
		"unnamed emergency": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: ""},
			},
			wantErr: errors.New("seals: emergency seal name cannot be empty"),
		},
		"two auto seals": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "pkcs11", Name: "emergency"},
			},
			wantErr: errors.New("seals: more than one primary (auto-seal) seal found"),
		},
		"two shamir seals": {
			seals: []*KMS{
				{Type: "shamir"},
				{Type: "shamir", Name: "emergency"},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"primary and emergency with same name": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: "default"},
			},
			wantErr: errors.New(`seals: ["default"] is not unique in the configuration`),
		},
		"migration auto-auto with unnamed emergency": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "transit", Disabled: true},
				{Type: "shamir"},
			},
			wantErr: errors.New("seals: emergency seal name cannot be empty"),
		},
		"migration auto-auto with emergency": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "transit", Disabled: true},
				{Type: "shamir", Name: "emergency"},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "transit", Disabled: true},
				{Type: "shamir", Name: "emergency"},
			},
		},
		"migration shamir-shamir with emergency": {
			seals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir", Name: "emergency"},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"migration auto-shamir with emergency": {
			seals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "pkcs11", Disabled: true},
				{Type: "shamir", Name: "emergency"},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"migration shamir-auto with emergency": {
			seals: []*KMS{
				{Type: "pkcs11"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir", Name: "emergency"},
			},
			wantSeals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Disabled: true},
				{Type: "shamir", Name: "emergency"},
			},
		},
		"same name of primary and secondary with emergency": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: "default"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New(`seals: ["default"] is not unique in the configuration`),
		},
		"three seals with two disabled": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: "emergency", Disabled: true},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one disabled seal found"),
		},
		"three seals with two auto seals": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "pkcs11", Name: "another"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one primary (auto-seal) seal found"),
		},
		"three seals with two shamirs": {
			seals: []*KMS{
				{Type: "shamir", Name: "default"},
				{Type: "shamir", Name: "emergency"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than one emergency (shamir) seal found"),
		},
		"four seals": {
			seals: []*KMS{
				{Type: "pkcs11", Name: "default"},
				{Type: "shamir", Name: "emergency"},
				{Type: "pkcs11", Name: "another"},
				{Type: "shamir", Disabled: true},
			},
			wantErr: errors.New("seals: more than three seals declared"),
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			err := CheckAndResolveSeals(tc.seals)
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.Equal(t, tc.wantSeals, tc.seals)
			} else {
				require.EqualError(t, err, tc.wantErr.Error())
			}
		})
	}
}
