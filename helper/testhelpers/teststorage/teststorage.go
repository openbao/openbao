// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package teststorage

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/mitchellh/go-testing-interface"
	"github.com/openbao/openbao/audit"
	auditFile "github.com/openbao/openbao/builtin/audit/file"
	auditSocket "github.com/openbao/openbao/builtin/audit/socket"
	auditSyslog "github.com/openbao/openbao/builtin/audit/syslog"
	logicalDb "github.com/openbao/openbao/builtin/logical/database"
	logicalKv "github.com/openbao/openbao/builtin/logical/kv"
	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/testhelpers"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	physFile "github.com/openbao/openbao/sdk/v2/physical/file"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"
	"github.com/openbao/openbao/vault"
)

func MakeInmemBackend(t testing.T, logger hclog.Logger) *vault.PhysicalBackendBundle {
	inm, err := inmem.NewInmem(nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	inmha, err := inmem.NewInmemHA(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	return &vault.PhysicalBackendBundle{
		Backend:   inm,
		HABackend: inmha.(physical.HABackend),
	}
}

func MakeLatentInmemBackend(t testing.T, logger hclog.Logger) *vault.PhysicalBackendBundle {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	jitter := r.Intn(20)
	latency := time.Duration(r.Intn(15)) * time.Millisecond

	pbb := MakeInmemBackend(t, logger)
	latencyInjector := physical.NewLatencyInjector(pbb.Backend, latency, jitter, logger)
	pbb.Backend = latencyInjector
	return pbb
}

func MakeFileBackend(t testing.T, logger hclog.Logger) *vault.PhysicalBackendBundle {
	path, err := os.MkdirTemp("", "vault-integ-file-")
	if err != nil {
		t.Fatal(err)
	}
	fileConf := map[string]string{
		"path": path,
	}
	fileBackend, err := physFile.NewFileBackend(fileConf, logger)
	if err != nil {
		t.Fatal(err)
	}

	inmha, err := inmem.NewInmemHA(nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	return &vault.PhysicalBackendBundle{
		Backend:   fileBackend,
		HABackend: inmha.(physical.HABackend),
		Cleanup: func() {
			err := os.RemoveAll(path)
			if err != nil {
				t.Fatal(err)
			}
		},
	}
}

func MakeRaftBackend(t testing.T, coreIdx int, logger hclog.Logger, extraConf map[string]interface{}) *vault.PhysicalBackendBundle {
	nodeID := fmt.Sprintf("core-%d", coreIdx)
	raftDir := t.TempDir()
	logger.Info("raft dir", "dir", raftDir)

	conf := map[string]string{
		"path":                   raftDir,
		"node_id":                nodeID,
		"performance_multiplier": "8",
	}
	for k, v := range extraConf {
		val, ok := v.(string)
		if ok {
			conf[k] = val
		}
	}

	backend, err := raft.NewRaftBackend(conf, logger.Named("raft"))
	if err != nil {
		t.Fatal(err)
	}

	return &vault.PhysicalBackendBundle{
		Backend: backend,
	}
}

// RaftHAFactory returns a PhysicalBackendBundle with raft set as the HABackend
// and the physical.Backend provided in PhysicalBackendBundler as the storage
// backend.
func RaftHAFactory(f PhysicalBackendBundler) func(t testing.T, coreIdx int, logger hclog.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
	return func(t testing.T, coreIdx int, logger hclog.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
		// Call the factory func to create the storage backend
		physFactory := SharedPhysicalFactory(f)
		bundle := physFactory(t, coreIdx, logger, nil)

		// This can happen if a shared physical backend is called on a non-0th core.
		if bundle == nil {
			bundle = new(vault.PhysicalBackendBundle)
		}

		raftDir := t.TempDir()
		nodeID := fmt.Sprintf("core-%d", coreIdx)
		backendConf := map[string]string{
			"path":                         raftDir,
			"node_id":                      nodeID,
			"performance_multiplier":       "8",
			"autopilot_reconcile_interval": "300ms",
			"autopilot_update_interval":    "100ms",
		}

		// Create and set the HA Backend
		raftBackend, err := raft.NewRaftBackend(backendConf, logger)
		if err != nil {
			bundle.Cleanup()
			t.Fatal(err)
		}
		bundle.HABackend = raftBackend.(physical.HABackend)

		// Re-wrap the cleanup func
		bundleCleanup := bundle.Cleanup
		bundle.Cleanup = func() {
			if bundleCleanup != nil {
				bundleCleanup()
			}
		}

		return bundle
	}
}

type PhysicalBackendBundler func(t testing.T, logger hclog.Logger) *vault.PhysicalBackendBundle

func SharedPhysicalFactory(f PhysicalBackendBundler) func(t testing.T, coreIdx int, logger hclog.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
	return func(t testing.T, coreIdx int, logger hclog.Logger, conf map[string]interface{}) *vault.PhysicalBackendBundle {
		if coreIdx == 0 {
			return f(t, logger)
		}
		return nil
	}
}

type ClusterSetupMutator func(conf *vault.CoreConfig, opts *vault.TestClusterOptions)

func InmemBackendSetup(conf *vault.CoreConfig, opts *vault.TestClusterOptions) {
	opts.PhysicalFactory = SharedPhysicalFactory(MakeInmemBackend)
}

func InmemLatentBackendSetup(conf *vault.CoreConfig, opts *vault.TestClusterOptions) {
	opts.PhysicalFactory = SharedPhysicalFactory(MakeLatentInmemBackend)
}

func FileBackendSetup(conf *vault.CoreConfig, opts *vault.TestClusterOptions) {
	opts.PhysicalFactory = SharedPhysicalFactory(MakeFileBackend)
}

func RaftBackendSetup(conf *vault.CoreConfig, opts *vault.TestClusterOptions) {
	opts.KeepStandbysSealed = true
	opts.PhysicalFactory = MakeRaftBackend
	opts.SetupFunc = func(t testing.T, c *vault.TestCluster) {
		if opts.NumCores != 1 {
			testhelpers.RaftClusterJoinNodes(t, c)
			time.Sleep(15 * time.Second)
		}
	}
}

func RaftHASetup(conf *vault.CoreConfig, opts *vault.TestClusterOptions, bundler PhysicalBackendBundler) {
	opts.KeepStandbysSealed = true
	opts.PhysicalFactory = RaftHAFactory(bundler)
}

func ClusterSetup(conf *vault.CoreConfig, opts *vault.TestClusterOptions, setup ClusterSetupMutator) (*vault.CoreConfig, *vault.TestClusterOptions) {
	var localConf vault.CoreConfig
	localConf.DisableAutopilot = true
	if conf != nil {
		localConf = *conf
	}
	localOpts := vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	}
	if opts != nil {
		localOpts = *opts
	}
	if setup == nil {
		setup = InmemBackendSetup
	}
	setup(&localConf, &localOpts)
	if localConf.CredentialBackends == nil {
		localConf.CredentialBackends = map[string]logical.Factory{
			"plugin": plugin.Factory,
		}
	}
	if localConf.LogicalBackends == nil {
		localConf.LogicalBackends = map[string]logical.Factory{
			"plugin":   plugin.Factory,
			"database": logicalDb.Factory,
			// This is also available in the plugin catalog, but is here due to the need to
			// automatically mount it.
			"kv": logicalKv.Factory,
		}
	}
	if localConf.AuditBackends == nil {
		localConf.AuditBackends = map[string]audit.Factory{
			"file":   auditFile.Factory,
			"socket": auditSocket.Factory,
			"syslog": auditSyslog.Factory,
			"noop":   corehelpers.NoopAuditFactory(nil),
		}
	}

	return &localConf, &localOpts
}
