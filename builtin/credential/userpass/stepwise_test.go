// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/policyutil"
	"github.com/openbao/openbao/sdk/v2/helper/stepwise"
	dockerEnvironment "github.com/openbao/openbao/sdk/v2/helper/stepwise/environments/docker"
)

func TestAccBackend_stepwise_UserCrud(t *testing.T) {
	customPluginName := "my-userpass"
	envOptions := &stepwise.MountOptions{
		RegistryName:    customPluginName,
		PluginType:      api.PluginTypeCredential,
		PluginName:      "userpass",
		MountPathPrefix: customPluginName,
	}
	stepwise.Run(t, stepwise.Case{
		Environment: dockerEnvironment.NewEnvironment(customPluginName, envOptions),
		Steps: []stepwise.Step{
			testAccStepwiseUser(t, "web", "password", "foo"),
			testAccStepwiseReadUser(t, "web", "foo"),
			testAccStepwiseDeleteUser(t, "web"),
			testAccStepwiseReadUser(t, "web", ""),
		},
	})
}

func testAccStepwiseUser(
	t *testing.T, name string, password string, policies string,
) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.UpdateOperation,
		Path:      "users/" + name,
		Data: map[string]interface{}{
			"password": password,
			"policies": policies,
		},
	}
}

func testAccStepwiseDeleteUser(t *testing.T, name string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.DeleteOperation,
		Path:      "users/" + name,
	}
}

func testAccStepwiseReadUser(t *testing.T, name string, policies string) stepwise.Step {
	return stepwise.Step{
		Operation: stepwise.ReadOperation,
		Path:      "users/" + name,
		Assert: func(resp *api.Secret, err error) error {
			if resp == nil {
				if policies == "" {
					return nil
				}

				return errors.New("unexpected nil response")
			}

			var d struct {
				Policies []string `mapstructure:"policies"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}

			expectedPolicies := policyutil.ParsePolicies(policies)
			if !reflect.DeepEqual(d.Policies, expectedPolicies) {
				return fmt.Errorf("Actual policies: %#v\nExpected policies: %#v", d.Policies, expectedPolicies)
			}

			return nil
		},
	}
}
