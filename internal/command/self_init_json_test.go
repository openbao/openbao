package command

import (
	"fmt"
	"testing"

	"github.com/hashicorp/cli"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/testhelpers/teststorage"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/vault"
	"github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
)

// TestSelfInitJSONConfig verifies the documented JSON form of the initialize
// stanza parses and executes end-to-end. hcl v1's JSON parser flattens
// nested objects so that block keys and their names fuse into single items,
// which historically caused the names of the outer block and its requests to
// be reported as unknown configuration fields (and, for the outer block's
// name, to abort startup).
func TestSelfInitJSONConfig(t *testing.T) {
	testSeal, _ := seal.NewTestSeal(nil)
	autoSeal, err := vault.NewAutoSeal(testSeal)
	require.NoError(t, err)

	logger := log.NewInterceptLogger(&log.LoggerOptions{Level: log.Debug})
	conf, opts := teststorage.ClusterSetup(&vault.CoreConfig{
		DisableCache:       true,
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
	t.Cleanup(cluster.Cleanup)

	cmd := &ServerCommand{
		BaseCommand: &BaseCommand{
			UI: cli.NewMockUi(),
		},
		ShutdownCh: MakeShutdownCh(),
		SighupCh:   MakeSighupCh(),
		SigUSR2Ch:  MakeSigUSR2Ch(),
		logger:     logger,
	}

	config, err := server.ParseConfig(fmt.Sprintf(`{
	"initialize": [
		{
			"kv": {
				"request": [
					{
						"mount-kv": {
							"operation": "update",
							"path": "sys/mounts/secret",
							"data": {
								"type": "kv",
								"options": {
									"version": "2"
								}
							}
						}
					}
				]
			}
		}
	]
}`), "self-init-json-test")
	require.NoError(t, err)
	require.Len(t, config.Initialization, 1)
	require.Empty(t, config.Validate("self-init-json-test"))

	require.NoError(t, cmd.Initialize(cluster.Cores[0].Core, config))

	// The mounted KV backend must exist, proving the JSON-described request
	// was actually executed against the core. The self-initialization flow
	// creates and then revokes its own root token, so we list mounts through
	// the core's public accessor instead of the HTTP API.
	mounts, err := cluster.Cores[0].Core.ListMounts()
	require.NoError(t, err)
	var foundKVMount bool
	for _, mount := range mounts {
		if mount.Path == "secret/" {
			foundKVMount = true
			require.Equal(t, "kv", mount.Type)
		}
	}
	require.True(t, foundKVMount, "expected secret/ to be mounted as kv by self-init")

}
