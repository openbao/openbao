// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/hclutil"
)

const (
	// DefaultConfigPath is the default path to the configuration file
	DefaultConfigPath = "~/.bao"

	// ConfigPathEnv is the environment variable that can be used to
	// override where the configuration file is.
	ConfigPathEnv = "BAO_CONFIG_PATH"
)

// Config is the CLI configuration for Bao that can be specified via
// `$BAO_CONFIG_PATH=$HOME/.bao` file which is HCL-formatted (therefore HCL or JSON).
type DefaultConfig struct {
	// TokenHelper is the executable/command that is executed for storing
	// and retrieving the authentication token for the Vault CLI. If this
	// is not specified, then OpenBao's internal token store will be used, which
	// stores the token on disk unencrypted.
	TokenHelper string `hcl:"token_helper"`
}

// Config loads the configuration and returns it. If the configuration
// is already loaded, it is returned.
func Config() (*DefaultConfig, error) {
	var err error
	config, err := LoadConfig("")
	if err != nil {
		return nil, err
	}

	return config, nil
}

// LoadConfig reads the configuration from the given path. If path is
// empty, then the default path will be used, or the environment variable
// if set.
func LoadConfig(path string) (*DefaultConfig, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	if v := api.ReadBaoVariable(ConfigPathEnv); v != "" {
		path = v
	}

	// NOTE: requires HOME env var to be set
	path, err := homedir.Expand(path)
	if err != nil {
		return nil, fmt.Errorf("error expanding config path %q: %w", path, err)
	}

	contents, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	conf, err := ParseConfig(string(contents))
	if err != nil {
		//nolint:staticcheck // user-facing error
		return nil, fmt.Errorf("error parsing config file at %q: %w; ensure that the file is valid; Ansible Vault is known to conflict with it.", path, err)
	}

	return conf, nil
}

// ParseConfig parses the given configuration as a string.
func ParseConfig(contents string) (*DefaultConfig, error) {
	root, err := hclutil.ParseConfig([]byte(contents))
	if err != nil {
		return nil, err
	}

	// Top-level item should be the object list
	list, ok := root.Node.(*ast.ObjectList)
	if !ok {
		return nil, errors.New("failed to parse config; does not contain a root object")
	}

	valid := []string{
		"token_helper",
	}
	if err := hclutil.CheckHCLKeys(list, valid); err != nil {
		return nil, err
	}

	var c DefaultConfig
	if err := hcl.DecodeObject(&c, list); err != nil {
		return nil, err
	}
	return &c, nil
}
