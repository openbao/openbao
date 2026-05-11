// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rabbitmq

import (
	"reflect"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestBackend_ConfigConnection_DefaultUsernameTemplate(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend()
	if err = b.Setup(t.Context(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"connection_uri":    "uri",
		"username":          "username",
		"password":          "password",
		"verify_connection": "false",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(t.Context(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}

	actualConfig, err := readConfig(t.Context(), config.StorageView)
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig := connectionConfig{
		URI:              "uri",
		Username:         "username",
		Password:         "password",
		UsernameTemplate: "",
	}

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig, actualConfig)
	}
}

func TestBackend_ConfigConnection_CustomUsernameTemplate(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b := Backend()
	if err = b.Setup(t.Context(), config); err != nil {
		t.Fatal(err)
	}

	configData := map[string]interface{}{
		"connection_uri":    "uri",
		"username":          "username",
		"password":          "password",
		"verify_connection": "false",
		"username_template": "{{ .DisplayName }}",
	}
	configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Storage:   config.StorageView,
		Data:      configData,
	}
	resp, err = b.HandleRequest(t.Context(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr:%s", resp, err)
	}
	if resp != nil {
		t.Fatal("expected a nil response")
	}

	actualConfig, err := readConfig(t.Context(), config.StorageView)
	if err != nil {
		t.Fatalf("unable to read configuration: %v", err)
	}

	expectedConfig := connectionConfig{
		URI:              "uri",
		Username:         "username",
		Password:         "password",
		UsernameTemplate: "{{ .DisplayName }}",
	}

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Fatalf("Expected: %#v\nActual: %#v", expectedConfig, actualConfig)
	}
}
