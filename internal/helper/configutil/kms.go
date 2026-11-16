// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/sdk/v2/helper/hclutil"
)

// KMS contains KMS configuration for the server
type KMS struct {
	UnusedKeys []string `hcl:",unusedKeys"`
	Type       string
	// Purpose can be used to allow a string-based specification of what this
	// KMS is designated for, in situations where we want to allow more than
	// one KMS to be specified
	Purpose []string `hcl:"-"`

	Disabled bool
	Config   map[string]string

	HealthCheckEnabled           bool          `hcl:"-"`
	HealthCheckTimeout           time.Duration `hcl:"-"`
	HealthCheckInterval          time.Duration `hcl:"-"`
	HealthCheckIntervalUnhealthy time.Duration `hcl:"-"`
}

const (
	DefaultSealHealthCheckTimeout           = 1 * time.Minute
	DefaultSealHealthCheckInterval          = 10 * time.Minute
	DefaultSealHealthCheckIntervalUnhealthy = 1 * time.Minute
)

func (k *KMS) GoString() string {
	return fmt.Sprintf("*%#v", *k)
}

func parseKMS(result *[]*KMS, list *ast.ObjectList, blockName string, maxKMS int) error {
	if len(list.Items) > maxKMS {
		return fmt.Errorf("only two or less %q blocks are permitted", blockName)
	}

	seals := make([]*KMS, 0, len(list.Items))
	for _, item := range list.Items {
		key := blockName
		if len(item.Keys) > 0 {
			key = item.Keys[0].Token.Value().(string)
		}

		// We first decode into a map[string]any because purpose isn't
		// necessarily a string. Then we migrate everything else over to
		// map[string]string and error if it doesn't work.
		var m map[string]any
		if err := hcl.DecodeObject(&m, item.Val); err != nil {
			return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
		}

		var purpose []string
		var err error
		if v, ok := m["purpose"]; ok {
			if purpose, err = parseutil.ParseCommaStringSlice(v); err != nil {
				return multierror.Prefix(fmt.Errorf("unable to parse 'purpose' in kms type %q: %w", key, err), fmt.Sprintf("%s.%s:", blockName, key))
			}
			for i, p := range purpose {
				purpose[i] = strings.ToLower(p)
			}
			delete(m, "purpose")
		}

		var disabled bool
		if v, ok := m["disabled"]; ok {
			disabled, err = parseutil.ParseBool(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			delete(m, "disabled")
		}

		healthCheckEnabled := true
		if v, ok := m["health_check_enabled"]; ok {
			healthCheckEnabled, err = parseutil.ParseBool(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s", blockName, key))
			}
			delete(m, "health_check_enabled")
		}

		healthCheckTimeout := DefaultSealHealthCheckTimeout
		if v, ok := m["health_check_timeout"]; ok {
			healthCheckTimeout, err = parseutil.ParseDurationSecond(v)
			switch {
			case err != nil:
				return multierror.Prefix(err, fmt.Sprintf("%s.%s", blockName, key))
			case healthCheckTimeout <= 0:
				return multierror.Prefix(
					fmt.Errorf("health_check_timeout cannot be less or equal to zero"),
					fmt.Sprintf("%s.%s", blockName, key),
				)
			}
			delete(m, "health_check_timeout")
		}

		healthCheckInterval := DefaultSealHealthCheckInterval
		if v, ok := m["health_check_interval"]; ok {
			healthCheckInterval, err = parseutil.ParseDurationSecond(v)
			switch {
			case err != nil:
				return multierror.Prefix(err, fmt.Sprintf("%s.%s", blockName, key))
			case healthCheckInterval <= 0:
				return multierror.Prefix(
					fmt.Errorf("health_check_interval cannot be less or equal to zero"),
					fmt.Sprintf("%s.%s", blockName, key),
				)
			}
			delete(m, "health_check_interval")
		}

		healthCheckIntervalUnhealthy := DefaultSealHealthCheckIntervalUnhealthy
		if v, ok := m["health_check_interval_unhealthy"]; ok {
			healthCheckIntervalUnhealthy, err = parseutil.ParseDurationSecond(v)
			switch {
			case err != nil:
				return multierror.Prefix(err, fmt.Sprintf("%s.%s", blockName, key))
			case healthCheckIntervalUnhealthy <= 0:
				return multierror.Prefix(
					fmt.Errorf("health_check_interval_unhealthy cannot be less or equal to zero"),
					fmt.Sprintf("%s.%s", blockName, key),
				)
			}
			delete(m, "health_check_interval_unhealthy")
		}

		strMap := make(map[string]string, len(m))
		for k, v := range m {
			s, err := parseutil.ParseString(v)
			if err != nil {
				return multierror.Prefix(err, fmt.Sprintf("%s.%s:", blockName, key))
			}
			strMap[k] = s
		}

		seal := &KMS{
			Type:                         strings.ToLower(key),
			Purpose:                      purpose,
			Disabled:                     disabled,
			HealthCheckEnabled:           healthCheckEnabled,
			HealthCheckTimeout:           healthCheckTimeout,
			HealthCheckInterval:          healthCheckInterval,
			HealthCheckIntervalUnhealthy: healthCheckIntervalUnhealthy,
		}
		if len(strMap) > 0 {
			seal.Config = strMap
		}
		seals = append(seals, seal)
	}

	*result = append(*result, seals...)

	return nil
}

func ParseKMSes(d string) ([]*KMS, error) {
	// Parse!
	obj, err := hclutil.ParseConfig([]byte(d))
	if err != nil {
		return nil, err
	}

	// Start building the result
	var result struct {
		Seals []*KMS `hcl:"-"`
	}

	if err := hcl.DecodeObject(&result, obj); err != nil {
		return nil, err
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("error parsing: file doesn't contain a root object")
	}

	if o := list.Filter("seal"); len(o.Items) > 0 {
		if err := parseKMS(&result.Seals, o, "seal", 3); err != nil {
			return nil, fmt.Errorf("error parsing 'seal': %w", err)
		}
	}

	if o := list.Filter("kms"); len(o.Items) > 0 {
		if err := parseKMS(&result.Seals, o, "kms", 3); err != nil {
			return nil, fmt.Errorf("error parsing 'kms': %w", err)
		}
	}

	return result.Seals, nil
}
