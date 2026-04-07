// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package workflows

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestWorkflow(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableCache: true,
		CredentialBackends: map[string]logical.Factory{
			"userpass": userpass.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"kv-v2": logicalKv.VersionedKVFactory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})

	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores

	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client

	t.Run("acceptance", func(t *testing.T) {
		_, err := client.Logical().Write("sys/namespaces/acceptance", map[string]any{})
		require.NoError(t, err)

		client := client.WithNamespace("acceptance")
		testWorkflowAcceptance(t, client)
	})

	t.Run("recursion", func(t *testing.T) {
		_, err := client.Logical().Write("sys/namespaces/recursion", map[string]any{})
		require.NoError(t, err)

		client := client.WithNamespace("recursion")
		testWorkflowRecursion(t, client)
	})
}

func testWorkflowAcceptance(t *testing.T, client *api.Client) {
	// No workflows to start.
	resp, err := client.Logical().List("sys/workflows/manage")
	require.NoError(t, err)
	require.Nil(t, resp)

	// Create a workflow.
	_, err = client.Logical().Write("sys/workflows/manage/create-namespace", map[string]interface{}{
		"workflow": createNamespaceWorkflow,
	})
	require.NoError(t, err)

	// Should exist.
	resp, err = client.Logical().List("sys/workflows/manage")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data["keys"], "create-namespace")

	// Should be able to execute it.
	workflowResp, err := client.Logical().Write("sys/workflows/execute/create-namespace", map[string]interface{}{
		"namespace": "test",
		"username":  "admin",
		"password":  "Secret123",
	})
	require.NoError(t, err)
	require.NotNil(t, workflowResp)
	require.Contains(t, workflowResp.Data["namespace"], "test")
	require.Contains(t, workflowResp.Data, "token")

	// Should be able to see the namespace.
	resp, err = client.Logical().List("sys/namespaces")
	require.NoError(t, err)
	require.Contains(t, resp.Data["keys"], "test/")

	// The token should work.
	testClient := client.WithNamespace("acceptance/test/")
	testClient.SetToken(workflowResp.Data["token"].(string))
	resp, err = testClient.Logical().Write("secret/data/test", map[string]interface{}{
		"data": map[string]interface{}{
			"a": "b",
		},
	})

	require.NoError(t, err)
	require.Nil(t, resp)

	resp, err = testClient.Logical().Read("secret/data/test")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data["data"], "a")

	// Cleaning up workflows should work.
	_, err = client.Logical().Delete("sys/workflows/manage/create-namespace")
	require.NoError(t, err)

	resp, err = client.Logical().List("sys/workflows/manage")
	require.NoError(t, err)
	require.Nil(t, resp)
}

func testWorkflowRecursion(t *testing.T, client *api.Client) {
	_, err := client.Logical().Write("sys/workflows/manage/endless-recursion", map[string]any{
		"workflow": endlessRecursionWorkflow,
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("sys/workflows/execute/endless-recursion", nil)
	require.Contains(t, err.Error(), "too much workflow recursion")
}

const createNamespaceWorkflow = `
input {
  fields "string" "namespace" {
    description = "name of the namespace to create"
    required = true
  }

  fields "string" "username" {
    description = "username to provision into auth mount"
    required = true
  }

  fields "string" "password" {
    description = "password to authenticate with"
    required = true
  }
}

flow "administration" {
  request "namespace" {
    operation = "create"
    path = {
      eval_source = "template"
      eval_type = "string"
      template = "sys/namespaces/{{ .input.namespace }}"
    }
  }

  request "auth" {
    operation = "create"
    path = {
      eval_type = "string"
      eval_source = "template"
      template = "{{ .input.namespace }}/sys/auth/userpass"
    }
    data = {
      type = "userpass"
    }
  }

  request "policy" {
    operation = "create"
    path = {
      eval_source = "template"
      eval_type = "string"
      template = "{{ .input.namespace }}/sys/policies/acl/ns-admin"
    }
    data = {
      policy = <<-EOT
      path "*" {
        capabilities = [ "create", "read", "update", "delete", "list", "sudo" ]
      }
      EOT
    }
  }

  request "admin" {
    operation = "create"
    path = {
      eval_source = "template"
      eval_type = "string"
      template = "{{ .input.namespace }}/auth/userpass/users/{{ .input.username }}"
    }
    data = {
      password = {
        eval_source = "input"
        eval_type = "string"
        field_name = "password"
      }
      token_policies = "default,ns-admin"
    }
  }

  request "secret" {
    operation = "create"
    path = {
      eval_source = "template"
      eval_type = "string"
      template = "{{ .input.namespace }}/sys/mounts/secret"
    }
    data = {
      type = "kv-v2"
    }
  }
}

flow "authentication" {
  request "login" {
    operation = "update"
    path = {
      eval_source = "template"
      eval_type = "string"
      template = "{{ .input.namespace }}/auth/userpass/login/{{ .input.username }}"
    }
    data = {
      password = {
        eval_source = "input"
        eval_type = "string"
        field_name = "password"
      }
    }
  }
}


output {
  data = {
    namespace = {
      eval_type = "string"
      eval_source = "input"
      field_name = "namespace"
    }
    token = {
      eval_type = "string"
      eval_source = "response"
      flow_name = "authentication"
      response_name = "login"
      field_selector = ["auth", "client_token"]
    }
  }
}
`

const endlessRecursionWorkflow = `
flow "loop" {
  request "recursion" {
    path = "sys/workflows/execute/endless-recursion"
    operation = "update"
  }
}
`
