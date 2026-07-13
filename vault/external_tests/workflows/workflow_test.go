// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package workflows

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/credential/userpass"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	logicalTotp "github.com/openbao/openbao/builtin/logical/totp"
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
			"totp":  logicalTotp.Factory,
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

	t.Run("mfa", func(t *testing.T) {
		_, err := client.Logical().Write("sys/namespaces/mfa", map[string]any{})
		require.NoError(t, err)

		client := client.WithNamespace("mfa")
		testWorkflowLoginMFA(t, client)
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

func testWorkflowLoginMFA(t *testing.T, client *api.Client) {
	// Create workflow.
	_, err := client.Logical().Write("sys/workflows/manage/setup-admin", map[string]interface{}{
		"workflow": loginMFAWorkflow,
	})
	require.NoError(t, err)

	// Should exist.
	resp, err := client.Logical().List("sys/workflows/manage")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data["keys"], "setup-admin")

	// Should be able to execute it.
	workflowResp, err := client.Logical().Write("sys/workflows/execute/setup-admin", map[string]interface{}{
		"username": "admin",
		"password": "Secret123",
	})
	require.NoError(t, err)
	require.NotNil(t, workflowResp)
	require.Contains(t, workflowResp.Data, "token")
	require.NotEmpty(t, workflowResp.Data["token"])

	// The token should work.
	testClient, err := client.Clone()
	require.NoError(t, err)

	testClient.SetToken(workflowResp.Data["token"].(string))
	resp, err = testClient.Logical().Read("auth/token/lookup-self")
	require.NoError(t, err)
	require.NotNil(t, resp)
}

const createNamespaceWorkflow = `
input {
  field "string" "namespace" {
    description = "name of the namespace to create"
    required = true
  }

  field "string" "username" {
    description = "username to provision into auth mount"
    required = true
  }

  field "string" "password" {
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

const loginMFAWorkflow = `
input {
  field "string" "username" {
    description = "username to provision into auth mount"
    required = true
  }

  field "string" "password" {
    description = "password to authenticate with"
    required = true
  }
}

flow "administration" {
  request "auth" {
    operation = "create"
    path = "sys/auth/userpass"
    data = {
      type = "userpass"
    }
  }

  request "auth-read" {
    operation = "read"
    path = "sys/auth/userpass"
  }

  request "policy" {
    operation = "create"
    path = "sys/policies/acl/admin"
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
      template = "auth/userpass/users/{{ .input.username }}"
    }
    data = {
      password = {
        eval_source = "input"
        eval_type = "string"
        field_name = "password"
      }
      token_policies = "default,admin"
    }
  }
}

flow "identity" {
  request "entity" {
    operation = "create"
    path = "identity/entity"
    data = {
      metadata = {
        testing = "true"
      }
    }
  }

  request "entity-alias" {
    operation = "create"
    path = "identity/entity-alias"
    data = {
      name = "admin"
      canonical_id = {
        eval_source = "response"
        eval_type = "string"
        flow_name = "identity"
        response_name = "entity"
        field_selector = ["data", "id"]
      }
      mount_accessor = {
        eval_source = "response"
        eval_type = "string"
        flow_name = "administration"
        response_name = "auth-read"
        field_selector = ["data", "accessor"]
      }
    }
  }
}

flow "mfa" {
  request "method" {
    operation = "create"
    path = "identity/mfa/method/totp"
    data = {
      method_name = "testing"
      issuer = "openbao"
    }
  }

  request "secret" {
    operation = "update"
    path = "identity/mfa/method/totp/admin-generate"
    data = {
      method_id = {
        eval_source = "response"
        eval_type = "string"
        flow_name = "mfa"
        response_name = "method"
        field_selector = ["data", "method_id"]
      }
      entity_id = {
        eval_source = "response"
        eval_type = "string"
        flow_name = "identity"
        response_name = "entity"
        field_selector = ["data", "id"]
      }
    }
  }

  request "enforce" {
    operation = "create"
    path = "identity/mfa/login-enforcement/admin"
    data = {
      mfa_method_ids = [
        {
          eval_source = "response"
          eval_type = "string"
          flow_name = "mfa"
          response_name = "method"
          field_selector = ["data", "method_id"]
        }
      ]
      identity_entity_ids = [
        {
          eval_source = "response"
          eval_type = "string"
          flow_name = "identity"
          response_name = "entity"
          field_selector = ["data", "id"]
        }
      ]
    }
  }

  request "totp-mount" {
    operation = "create"
    path = "sys/mounts/totp"
    data = {
      type = "totp"
    }
  }

  request "totp-import" {
    operation = "create"
    path = "totp/keys/mfa"
    data = {
      url = {
        eval_source = "response"
        eval_type = "string"
        flow_name = "mfa"
        response_name = "secret"
        field_selector = ["data", "url"]
      }
    }
  }
}

flow "authentication" {
  request "mfa" {
    operation = "read"
    path = "totp/code/mfa"
  }

  request "login" {
    operation = "update"
    path = {
      eval_source = "template"
      eval_type = "string"
      template = "auth/userpass/login/{{ .input.username }}"
    }
	headers = {
	  "X-Vault-MFA" = {
		eval_source = "template"
		eval_type = "string"
		template = "{{ .responses.mfa.method.data.method_id }}:{{ .responses.authentication.mfa.data.code }}"
	  }
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
