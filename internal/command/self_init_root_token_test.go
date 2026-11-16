package command

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/cli"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
)

const testSelfInitProofToken = "self-init-proof-reader"

func TestSelfInitRevokesRootToken(t *testing.T) {
	tests := []struct {
		name             string
		disableSSCTokens bool
		explicitRevoke   bool
		failAfterCapture bool
		wantErr          bool
	}{
		{
			name:             "success",
			disableSSCTokens: true,
		},
		{
			name: "ssc_tokens",
		},
		{
			name:             "explicit_revoke_self",
			disableSSCTokens: true,
			explicitRevoke:   true,
		},
		{
			name:             "failure_after_capture",
			disableSSCTokens: true,
			failAfterCapture: true,
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, core, cleanup := testSelfInitCore(t, tt.disableSSCTokens)
			t.Cleanup(cleanup)

			config := testSelfInitRootTokenConfig(t, tt.explicitRevoke, tt.failAfterCapture)
			err := cmd.Initialize(core, config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			rootToken := testSelfInitCapturedRootToken(t, core)
			entry, err := core.LookupToken(namespace.RootContext(context.Background()), rootToken)
			require.NoError(t, err)
			require.Nil(t, entry)
		})
	}
}

func testSelfInitCore(t *testing.T, disableSSCTokens bool) (*ServerCommand, *vault.Core, func()) {
	t.Helper()

	testSeal, _ := seal.NewTestSeal(nil)
	autoSeal, err := vault.NewAutoSeal(testSeal)
	require.NoError(t, err)

	logger := log.NewInterceptLogger(&log.LoggerOptions{Level: log.Debug})
	conf, opts := teststorage.ClusterSetup(&vault.CoreConfig{
		DisableCache:       true,
		DisableSSCTokens:   disableSSCTokens,
		Logger:             logger,
		Seal:               autoSeal,
		CredentialBackends: defaultVaultCredentialBackends,
		AuditBackends:      defaultVaultAuditBackends,
		LogicalBackends:    defaultVaultLogicalBackends,
	}, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		Logger:      logger,
		NumCores:    1,
		SkipInit:    true,
	}, nil)

	cluster := vault.NewTestCluster(t, conf, opts)
	cluster.Start()

	cmd := &ServerCommand{
		BaseCommand: &BaseCommand{
			UI: cli.NewMockUi(),
		},
		ShutdownCh: MakeShutdownCh(),
		SighupCh:   MakeSighupCh(),
		SigUSR2Ch:  MakeSigUSR2Ch(),
		logger:     logger,
	}

	return cmd, cluster.Cores[0].Core, cluster.Cleanup
}

func testSelfInitRootTokenConfig(t *testing.T, explicitRevoke, failAfterCapture bool) *server.Config {
	t.Helper()

	var revokeSelf string
	if explicitRevoke {
		revokeSelf = `
  request "revoke-self" {
    operation = "update"
    path      = "auth/token/revoke-self"
  }
`
	}

	var fail string
	if failAfterCapture {
		fail = `
  request "fail-duplicate-mount" {
    operation = "update"
    path      = "sys/mounts/secret"
    data = {
      type = "kv"
    }
  }
`
	}

	config, err := server.ParseConfig(fmt.Sprintf(`
initialize "proof" {
  request "mount-kv" {
    operation = "update"
    path      = "sys/mounts/secret"
    data = {
      type = "kv"
      options = {
        version = "2"
      }
    }
  }

  request "add-proof-reader-policy" {
    operation = "update"
    path      = "sys/policies/acl/proof-reader"
    data = {
      policy = <<-EOF
        path "secret/data/root-token-proof" {
          capabilities = ["read"]
        }
      EOF
    }
  }

  request "create-proof-token" {
    operation = "update"
    path      = "auth/token/create"
    data = {
      id                = %q
      policies          = ["proof-reader"]
      no_parent         = true
      no_default_policy = true
    }
  }

  request "lookup-self" {
    operation = "read"
    path      = "auth/token/lookup-self"
  }

  request "capture-root-token" {
    operation = "update"
    path      = "secret/data/root-token-proof"
    data = {
      data = {
        token = {
          eval_source     = "response"
          eval_type       = "string"
          initialize_name = "proof"
          response_name   = "lookup-self"
          field_selector  = ["data", "id"]
        }
      }
    }
  }
%s%s
}
`, testSelfInitProofToken, revokeSelf, fail), "self-init-root-token-test")
	require.NoError(t, err)

	return config
}

func testSelfInitCapturedRootToken(t *testing.T, core *vault.Core) string {
	t.Helper()

	ctx := namespace.RootContext(context.Background())
	resp, err := core.HandleRequest(ctx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "secret/data/root-token-proof",
		ClientToken: testSelfInitProofToken,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), resp.Error())

	data, ok := resp.Data["data"].(map[string]any)
	require.True(t, ok)
	token, ok := data["token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, token)

	return token
}
