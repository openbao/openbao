// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kubesecrets

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	rbacv1 "k8s.io/api/rbac/v1"
)

func Test_makeRules(t *testing.T) {
	testCases := map[string]struct {
		rules    string
		expected []rbacv1.PolicyRule
		wantErr  error
	}{
		"good YAML": {
			rules: goodYAMLRules,
			expected: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"admissionregistration.k8s.io"},
					Resources: []string{"mutatingwebhookconfigurations"},
					Verbs:     []string{"get", "list", "watch", "patch"},
				},
			},
			wantErr: nil,
		},
		"good JSON": {
			rules: goodJSONRules,
			expected: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"admissionregistration.k8s.io"},
					Resources: []string{"mutatingwebhookconfigurations"},
					Verbs:     []string{"get", "list", "watch", "patch"},
				},
			},
			wantErr: nil,
		},
		"bad YAML": {
			rules:    badYAMLRules,
			expected: nil,
			wantErr:  errors.New("error converting YAML to JSON: yaml: line 3: found character that cannot start any token"),
		},
		"bad JSON": {
			rules:    badJSONRules,
			expected: nil,
			wantErr:  errors.New("error converting YAML to JSON: yaml: line 4: did not find expected ',' or '}'"),
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result, err := makeRules(tc.rules)
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}
