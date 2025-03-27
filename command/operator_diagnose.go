// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"

	"github.com/hashicorp/cli"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	uuid "github.com/hashicorp/go-uuid"

	bApi "github.com/openbao/openbao/api/v2"
	cserver "github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/metricsutil"
	"github.com/openbao/openbao/internalshared/configutil"
	"github.com/openbao/openbao/internalshared/listenerutil"
	"github.com/openbao/openbao/physical/raft"
	"github.com/openbao/openbao/sdk/v2/physical"
	sr "github.com/openbao/openbao/serviceregistration"
	"github.com/openbao/openbao/vault"
	"github.com/openbao/openbao/vault/diagnose"
	"github.com/openbao/openbao/version"
	"github.com/posener/complete"
	"golang.org/x/term"
)

const CoreConfigUninitializedErr = "Diagnose cannot attempt this step because core config could not be set."

var (
	_ cli.Command             = (*OperatorDiagnoseCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorDiagnoseCommand)(nil)
)

type OperatorDiagnoseCommand struct {
	*BaseCommand
	diagnose *diagnose.Session

	flagDebug    bool
	flagSkips    []string
	flagConfigs  []string
	cleanupGuard sync.Once

	reloadFuncsLock      *sync.RWMutex
	reloadFuncs          *map[string][]reloadutil.ReloadFunc
	ServiceRegistrations map[string]sr.Factory
	startedCh            chan struct{} // for tests
	reloadedCh           chan struct{} // for tests
	skipEndEnd           bool          // for tests
}

func (c *OperatorDiagnoseCommand) Synopsis() string {
	return "Troubleshoot problems starting OpenBao"
}

func (c *OperatorDiagnoseCommand) Help() string {
	helpText := `
Usage: bao operator diagnose

  This command troubleshoots OpenBao startup issues, such as TLS configuration or
  auto-unseal. It should be run using the same environment variables and configuration
  files as the "bao server" command, so that startup problems can be accurately
  reproduced.

  Start diagnose with a configuration file:
    
     $ bao operator diagnose -config=/etc/openbao/config.hcl

  Perform a diagnostic check while OpenBao is still running:

     $ bao operator diagnose -config=/etc/openbao/config.hcl -skip=listener

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *OperatorDiagnoseCommand) Flags() *FlagSets {
	set := NewFlagSets(c.UI)
	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
			complete.PredictDirs("*"),
		),
		Usage: "Path to an OpenBao configuration file or directory of configuration " +
			"files. This flag can be specified multiple times to load multiple " +
			"configurations. If the path is a directory, all files which end in " +
			".hcl or .json are loaded.",
	})

	f.StringSliceVar(&StringSliceVar{
		Name:   "skip",
		Target: &c.flagSkips,
		Usage:  "Skip the health checks named as arguments. May be 'listener', 'storage', or 'autounseal'.",
	})

	f.BoolVar(&BoolVar{
		Name:    "debug",
		Target:  &c.flagDebug,
		Default: false,
		Usage:   "Dump all information collected by Diagnose.",
	})

	f.StringVar(&StringVar{
		Name:   "format",
		Target: &c.flagFormat,
		Usage:  "The output format",
	})
	return set
}

func (c *OperatorDiagnoseCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *OperatorDiagnoseCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

const (
	status_unknown = "[      ] "
	status_ok      = "\u001b[32m[  ok  ]\u001b[0m "
	status_failed  = "\u001b[31m[failed]\u001b[0m "
	status_warn    = "\u001b[33m[ warn ]\u001b[0m "
	same_line      = "\u001b[F"
)

func (c *OperatorDiagnoseCommand) Run(args []string) int {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 3
	}
	return c.RunWithParsedFlags()
}

func (c *OperatorDiagnoseCommand) RunWithParsedFlags() int {
	if len(c.flagConfigs) == 0 {
		c.UI.Error("Must specify a configuration file using -config.")
		return 3
	}

	if c.diagnose == nil {
		if c.flagFormat == "json" {
			c.diagnose = diagnose.New(io.Discard)
		} else {
			c.UI.Output(version.GetVersion().FullVersionNumber(true))
			c.diagnose = diagnose.New(os.Stdout)
		}
	}
	ctx := diagnose.Context(context.Background(), c.diagnose)
	c.diagnose.SkipFilters = c.flagSkips
	err := c.offlineDiagnostics(ctx)

	results := c.diagnose.Finalize(ctx)
	if c.flagFormat == "json" {
		resultsJS, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling results: %v.", err)
			return 4
		}
		c.UI.Output(string(resultsJS))
	} else {
		c.UI.Output("\nResults:")
		w, _, err := term.GetSize(0)
		if err == nil {
			results.Write(os.Stdout, w)
		} else {
			results.Write(os.Stdout, 0)
		}
	}

	if err != nil {
		return 4
	}
	// Use a different return code
	switch results.Status {
	case diagnose.WarningStatus:
		return 2
	case diagnose.ErrorStatus:
		return 1
	}
	return 0
}

func (c *OperatorDiagnoseCommand) offlineDiagnostics(ctx context.Context) error {
	rloadFuncs := make(map[string][]reloadutil.ReloadFunc)
	server := &ServerCommand{
		// TODO: set up a different one?
		// In particular, a UI instance that won't output?
		BaseCommand: c.BaseCommand,

		// TODO: refactor to a common place?
		AuditBackends:        auditBackends,
		CredentialBackends:   credentialBackends,
		LogicalBackends:      logicalBackends,
		PhysicalBackends:     physicalBackends,
		ServiceRegistrations: serviceRegistrations,

		// TODO: other ServerCommand options?

		logger: log.NewInterceptLogger(&log.LoggerOptions{
			Level: log.Off,
		}),
		allLoggers:      []log.Logger{},
		reloadFuncs:     &rloadFuncs,
		reloadFuncsLock: new(sync.RWMutex),
	}

	ctx, span := diagnose.StartSpan(ctx, "Vault Diagnose")
	defer span.End()

	// OS Specific checks
	diagnose.OSChecks(ctx)

	var config *cserver.Config

	diagnose.Test(ctx, "Parse Configuration", func(ctx context.Context) (err error) {
		server.flagConfigs = c.flagConfigs
		var configErrors []configutil.ConfigError
		config, configErrors, err = server.parseConfig()
		if err != nil {
			return fmt.Errorf("Could not parse configuration: %w.", err)
		}
		for _, ce := range configErrors {
			diagnose.Warn(ctx, diagnose.CapitalizeFirstLetter(ce.String())+".")
		}
		diagnose.Success(ctx, "Vault configuration syntax is ok.")
		return nil
	})
	if config == nil {
		return errors.New("No vault server configuration found.")
	}

	diagnose.Test(ctx, "Check Telemetry", func(ctx context.Context) (err error) {
		if config.Telemetry == nil {
			diagnose.Warn(ctx, "Telemetry is using default configuration")
			diagnose.Advise(ctx, "By default only Prometheus and JSON metrics are available.  Ignore this warning if you are using telemetry or are using these metrics and are satisfied with the default retention time and gauge period.")
		} else {
			t := config.Telemetry
			// If any Circonus setting is present but we're missing the basic fields...
			if coalesce(t.CirconusAPIURL, t.CirconusAPIToken, t.CirconusCheckID, t.CirconusCheckTags, t.CirconusCheckSearchTag,
				t.CirconusBrokerID, t.CirconusBrokerSelectTag, t.CirconusCheckForceMetricActivation, t.CirconusCheckInstanceID,
				t.CirconusCheckSubmissionURL, t.CirconusCheckDisplayName) != nil {
				if t.CirconusAPIURL == "" {
					return errors.New("incomplete Circonus telemetry configuration, missing circonus_api_url")
				} else if t.CirconusAPIToken != "" {
					return errors.New("incomplete Circonus telemetry configuration, missing circonus_api_token")
				}
			}
			if len(t.DogStatsDTags) > 0 && t.DogStatsDAddr == "" {
				return errors.New("incomplete DogStatsD telemetry configuration, missing dogstatsd_addr, while dogstatsd_tags specified")
			}

			// If any Stackdriver setting is present but we're missing the basic fields...
			if coalesce(t.StackdriverNamespace, t.StackdriverLocation, t.StackdriverDebugLogs, t.StackdriverNamespace) != nil {
				if t.StackdriverProjectID == "" {
					return errors.New("incomplete Stackdriver telemetry configuration, missing stackdriver_project_id")
				}
				if t.StackdriverLocation == "" {
					return errors.New("incomplete Stackdriver telemetry configuration, missing stackdriver_location")
				}
				if t.StackdriverNamespace == "" {
					return errors.New("incomplete Stackdriver telemetry configuration, missing stackdriver_namespace")
				}
			}
		}
		return nil
	})

	var metricSink *metricsutil.ClusterMetricSink
	var metricsHelper *metricsutil.MetricsHelper

	var backend *physical.Backend
	diagnose.Test(ctx, "Check Storage", func(ctx context.Context) error {
		// Ensure that there is a storage stanza
		if config.Storage == nil {
			diagnose.Advise(ctx, "To learn how to specify a storage backend, see the Vault server configuration documentation.")
			return errors.New("No storage stanza in Vault server configuration.")
		}

		diagnose.Test(ctx, "Create Storage Backend", func(ctx context.Context) error {
			b, err := server.setupStorage(config)
			if err != nil {
				return err
			}
			if b == nil {
				diagnose.Advise(ctx, "To learn how to specify a storage backend, see the Vault server configuration documentation.")
				return errors.New("Storage backend could not be initialized.")
			}
			backend = &b
			return nil
		})

		if backend == nil {
			diagnose.Fail(ctx, "Diagnose could not initialize storage backend.")
			span.End()
			return errors.New("Diagnose could not initialize storage backend.")
		}

		// Check for raft quorum status
		if config.Storage.Type == storageTypeRaft {
			path := bApi.ReadBaoVariable(raft.EnvVaultRaftPath)
			if path == "" {
				path, ok := config.Storage.Config["path"]
				if !ok {
					diagnose.SpotError(ctx, "Check Raft Folder Permissions", errors.New("Storage folder path is required."))
				}
				diagnose.RaftFileChecks(ctx, path)
			}
			diagnose.RaftStorageQuorum(ctx, (*backend).(*raft.RaftBackend))
		}

		// Attempt to use storage backend
		if !c.skipEndEnd && config.Storage.Type != storageTypeRaft {
			diagnose.Test(ctx, "Check Storage Access", diagnose.WithTimeout(30*time.Second, func(ctx context.Context) error {
				maxDurationCrudOperation := "write"
				maxDuration := time.Duration(0)
				uuidSuffix, err := uuid.GenerateUUID()
				if err != nil {
					return err
				}
				uuid := "diagnose/latency/" + uuidSuffix
				dur, err := diagnose.EndToEndLatencyCheckWrite(ctx, uuid, *backend)
				if err != nil {
					return err
				}
				maxDuration = dur
				dur, err = diagnose.EndToEndLatencyCheckRead(ctx, uuid, *backend)
				if err != nil {
					return err
				}
				if dur > maxDuration {
					maxDuration = dur
					maxDurationCrudOperation = "read"
				}
				dur, err = diagnose.EndToEndLatencyCheckDelete(ctx, uuid, *backend)
				if err != nil {
					return err
				}
				if dur > maxDuration {
					maxDuration = dur
					maxDurationCrudOperation = "delete"
				}

				if maxDuration > time.Duration(0) {
					diagnose.Warn(ctx, diagnose.LatencyWarning+fmt.Sprintf("duration: %s, operation: %s", maxDuration, maxDurationCrudOperation))
				}
				return nil
			}))
		}
		return nil
	})

	// Return from top-level span when backend is nil
	if backend == nil {
		return errors.New("Diagnose could not initialize storage backend.")
	}

	var configSR sr.ServiceRegistration
	diagnose.Test(ctx, "Check Service Discovery", func(ctx context.Context) error {
		if config.ServiceRegistration == nil || config.ServiceRegistration.Config == nil {
			diagnose.Skipped(ctx, "No service registration configured.")
			return nil
		}

		return nil
	})

	sealcontext, sealspan := diagnose.StartSpan(ctx, "Create Vault Server Configuration Seals")
	var seals []vault.Seal
	var sealConfigError error

	barrierSeal, barrierWrapper, unwrapSeal, seals, sealConfigError, err := setSeal(server, config, make([]string, 0), make(map[string]string))
	// Check error here
	if err != nil {
		diagnose.Advise(ctx, "For assistance with the seal stanza, see the Vault configuration documentation.")
		diagnose.Fail(sealcontext, fmt.Sprintf("Seal creation resulted in the following error: %s.", err.Error()))
		goto SEALFAIL
	}
	if sealConfigError != nil {
		diagnose.Fail(sealcontext, "Seal could not be configured: seals may already be initialized.")
		goto SEALFAIL
	}

	for _, seal := range seals {
		// There is always one nil seal. We need to skip it so we don't start an empty Finalize-Seal-Shamir
		// section.
		if seal == nil {
			continue
		}
		seal := seal // capture range variable
		// Ensure that the seal finalizer is called, even if using verify-only
		defer func(seal *vault.Seal) {
			sealType := diagnose.CapitalizeFirstLetter((*seal).BarrierType().String())
			finalizeSealContext, finalizeSealSpan := diagnose.StartSpan(ctx, "Finalize "+sealType+" Seal")
			err = (*seal).Finalize(finalizeSealContext)
			if err != nil {
				diagnose.Fail(finalizeSealContext, "Error finalizing seal.")
				diagnose.Advise(finalizeSealContext, "This likely means that the barrier is still in use; therefore, finalizing the seal timed out.")
				finalizeSealSpan.End()
			}
			finalizeSealSpan.End()
		}(&seal)
	}

	if barrierSeal == nil {
		diagnose.Fail(sealcontext, "Could not create barrier seal. No error was generated, but it is likely that the seal stanza is misconfigured. For guidance, see Vault's configuration documentation on the seal stanza.")
	}

SEALFAIL:
	sealspan.End()

	diagnose.Test(ctx, "Check Transit Seal TLS", func(ctx context.Context) error {
		var checkSealTransit bool
		for _, seal := range config.Seals {
			if seal.Type == "transit" {
				checkSealTransit = true

				tlsSkipVerify, _ := seal.Config["tls_skip_verify"]
				if tlsSkipVerify == "true" {
					diagnose.Warn(ctx, "TLS verification is skipped. This is highly discouraged and decreases the security of data transmissions to and from the Vault server.")
					return nil
				}

				// Checking tls_client_cert and tls_client_key
				tlsClientCert, ok := seal.Config["tls_client_cert"]
				if !ok {
					diagnose.Warn(ctx, "Missing tls_client_cert in the seal configuration.")
					return nil
				}
				tlsClientKey, ok := seal.Config["tls_client_key"]
				if !ok {
					diagnose.Warn(ctx, "Missing tls_client_key in the seal configuration.")
					return nil
				}
				_, err := diagnose.TLSFileChecks(tlsClientCert, tlsClientKey)
				if err != nil {
					return fmt.Errorf("The TLS certificate and key configured through the tls_client_cert and tls_client_key fields of the transit seal configuration are invalid: %w.", err)
				}

				// checking tls_ca_cert
				tlsCACert, ok := seal.Config["tls_ca_cert"]
				if !ok {
					diagnose.Warn(ctx, "Missing tls_ca_cert in the seal configuration.")
					return nil
				}
				warnings, err := diagnose.TLSCAFileCheck(tlsCACert)
				if len(warnings) != 0 {
					for _, warning := range warnings {
						diagnose.Warn(ctx, warning)
					}
				}
				if err != nil {
					return fmt.Errorf("The TLS CA certificate configured through the tls_ca_cert field of the transit seal configuration is invalid: %w.", err)
				}
			}
		}
		if !checkSealTransit {
			diagnose.Skipped(ctx, "No transit seal found in seal configuration.")
		}
		return nil
	})

	var coreConfig vault.CoreConfig
	diagnose.Test(ctx, "Create Core Configuration", func(ctx context.Context) error {
		var secureRandomReader io.Reader
		// prepare a secure random reader for core
		randReaderTestName := "Initialize Randomness for Core"
		secureRandomReader, err = configutil.CreateSecureRandomReaderFunc(config.SharedConfig, barrierWrapper)
		if err != nil {
			return diagnose.SpotError(ctx, randReaderTestName, fmt.Errorf("Could not initialize randomness for core: %w.", err))
		}
		diagnose.SpotOk(ctx, randReaderTestName, "")
		coreConfig = createCoreConfig(server, config, *backend, configSR, barrierSeal, unwrapSeal, metricsHelper, metricSink, secureRandomReader)
		return nil
	})

	var disableClustering bool
	diagnose.Test(ctx, "HA Storage", func(ctx context.Context) error {
		diagnose.Test(ctx, "Create HA Storage Backend", func(ctx context.Context) error {
			// Initialize the separate HA storage backend, if it exists
			disableClustering, err = initHaBackend(server, config, &coreConfig, *backend)
			if err != nil {
				return err
			}
			return nil
		})

		diagnose.Test(ctx, "Check HA Consul Direct Storage Access", func(ctx context.Context) error {
			if config.HAStorage == nil {
				diagnose.Skipped(ctx, "No HA storage stanza is configured.")
			} else {
				dirAccess := diagnose.ConsulDirectAccess(config.HAStorage.Config)
				if dirAccess != "" {
					diagnose.Warn(ctx, dirAccess)
				}
				if dirAccess == diagnose.DirAccessErr {
					diagnose.Advise(ctx, diagnose.DirAccessAdvice)
				}
			}
			return nil
		})
		return nil
	})

	// Determine the redirect address from environment variables
	err = determineRedirectAddr(server, &coreConfig, config)
	if err != nil {
		return diagnose.SpotError(ctx, "Determine Redirect Address", fmt.Errorf("Redirect Address could not be determined: %w.", err))
	}
	diagnose.SpotOk(ctx, "Determine Redirect Address", "")

	err = findClusterAddress(server, &coreConfig, config, disableClustering)
	if err != nil {
		return diagnose.SpotError(ctx, "Check Cluster Address", fmt.Errorf("Cluster Address could not be determined or was invalid: %w.", err),
			diagnose.Advice("Please check that the API and Cluster addresses are different, and that the API, Cluster and Redirect addresses have both a host and port."))
	}
	diagnose.SpotOk(ctx, "Check Cluster Address", "Cluster address is logically valid and can be found.")

	var vaultCore *vault.Core

	// Run all the checks that are utilized when initializing a core object
	// without actually calling core.Init. These are in the init-core section
	// as they are runtime checks.
	diagnose.Test(ctx, "Check Core Creation", func(ctx context.Context) error {
		var newCoreError error
		if coreConfig.RawConfig == nil {
			return fmt.Errorf(CoreConfigUninitializedErr)
		}
		core, newCoreError := vault.CreateCore(&coreConfig)
		if newCoreError != nil {
			if vault.IsFatalError(newCoreError) {
				return fmt.Errorf("Error initializing core: %s.", newCoreError)
			}
			diagnose.Warn(ctx, wrapAtLength(
				"A non-fatal error occurred during initialization. Please check the logs for more information."))
		} else {
			vaultCore = core
		}
		return nil
	})

	if vaultCore == nil {
		return errors.New("Diagnose could not initialize the Vault core from the Vault server configuration.")
	}

	var lns []listenerutil.Listener
	diagnose.Test(ctx, "Start Listeners", func(ctx context.Context) error {
		disableClustering := config.HAStorage != nil && config.HAStorage.DisableClustering
		infoKeys := make([]string, 0, 10)
		info := make(map[string]string)
		var listeners []listenerutil.Listener
		var status int

		diagnose.ListenerChecks(ctx, config.Listeners)

		diagnose.Test(ctx, "Create Listeners", func(ctx context.Context) error {
			status, listeners, _, err = server.InitListeners(nil, config, disableClustering, &infoKeys, &info)
			if status != 0 {
				return err
			}
			return nil
		})

		lns = listeners

		// Make sure we close all listeners from this point on
		listenerCloseFunc := func() {
			for _, ln := range lns {
				ln.Listener.Close()
			}
		}

		c.cleanupGuard.Do(listenerCloseFunc)

		return nil
	})

	// TODO: Diagnose logging configuration

	// The unseal diagnose check will simply attempt to use the barrier to encrypt and
	// decrypt a mock value. It will not call runUnseal.
	diagnose.Test(ctx, "Check Autounseal Encryption", diagnose.WithTimeout(30*time.Second, func(ctx context.Context) error {
		if barrierSeal == nil {
			return errors.New("Diagnose could not create a barrier seal object.")
		}
		if barrierSeal.BarrierType() == wrapping.WrapperTypeShamir {
			diagnose.Skipped(ctx, "Skipping barrier encryption test. Only supported for auto-unseal.")
			return nil
		}
		barrierUUID, err := uuid.GenerateUUID()
		if err != nil {
			return errors.New("Diagnose could not create unique UUID for unsealing.")
		}
		barrierEncValue := "diagnose-" + barrierUUID
		ciphertext, err := barrierWrapper.Encrypt(ctx, []byte(barrierEncValue), nil)
		if err != nil {
			return fmt.Errorf("Error encrypting with seal barrier: %w.", err)
		}
		plaintext, err := barrierWrapper.Decrypt(ctx, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("Error decrypting with seal barrier: %w", err)
		}
		if string(plaintext) != barrierEncValue {
			return errors.New("Barrier returned incorrect decrypted value for mock data.")
		}
		return nil
	}))

	// The following block contains static checks that are run during the
	// startHttpServers portion of server run. In other words, they are static
	// checks during resource creation. Currently there is nothing important in this
	// diagnose check. For now it is a placeholder for any checks that will be done
	// before server run.
	diagnose.Test(ctx, "Check Server Before Runtime", func(ctx context.Context) error {
		for _, ln := range lns {
			if ln.Config == nil {
				return errors.New("Found no listener config after parsing the Vault configuration.")
			}
		}
		return nil
	})

	return nil
}

func coalesce(values ...interface{}) interface{} {
	for _, val := range values {
		if val != nil && val != "" {
			return val
		}
	}
	return nil
}
