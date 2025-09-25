// Copyright The OpenBao Contributors
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package template is responsible for rendering user supplied templates to
// disk. The Server type accepts configuration to communicate to a Vault server
// and a Vault token for authentication. Internally, the Server creates a Consul
// Template Runner which manages reading secrets from Vault and rendering
// templates to disk at configured locations
package template

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-hclog"
	ctconfig "github.com/openbao/openbao-template/config"
	"github.com/openbao/openbao-template/manager"

	"github.com/openbao/openbao/command/agent/config"
	"github.com/openbao/openbao/command/agent/internal/ctmanager"
	"github.com/openbao/openbao/helper/useragent"
	"github.com/openbao/openbao/sdk/v2/helper/pointerutil"
)

const (
	defaultMinBackoff          = 1 * time.Second
	defaultMaxBackoff          = 5 * time.Minute
	backoffMultiplier          = 2
	backoffRandomizationFactor = 0.25
)

// ServerConfig is a config struct for setting up the basic parts of the
// Server
type ServerConfig struct {
	Logger hclog.Logger
	// Client        *api.Client
	AgentConfig *config.Config

	ExitAfterAuth bool
	Namespace     string

	MaxBackoff time.Duration
	MinBackoff time.Duration

	// LogLevel is needed to set the internal Consul Template Runner's log level
	// to match the log level of Vault Agent. The internal Runner creates it's own
	// logger and can't be set externally or copied from the Template Server.
	//
	// LogWriter is needed to initialize Consul Template's internal logger to use
	// the same io.Writer that Vault Agent itself is using.
	LogLevel  hclog.Level
	LogWriter io.Writer
}

// Server manages the Consul Template Runner which renders templates
type Server struct {
	// config holds the ServerConfig used to create it. It's passed along in other
	// methods
	config *ServerConfig

	// runner is the consul-template runner
	runner        *manager.Runner
	runnerStarted *atomic.Bool

	// Templates holds the parsed Consul Templates
	Templates []*ctconfig.TemplateConfig

	// lookupMap is a list of templates indexed by their consul-template ID. This
	// is used to ensure all Vault templates have been rendered before returning
	// from the runner in the event we're using exit after auth.
	lookupMap map[string][]*ctconfig.TemplateConfig

	DoneCh  chan struct{}
	stopped *atomic.Bool

	maxBackoff time.Duration
	minBackoff time.Duration

	logger        hclog.Logger
	exitAfterAuth bool
}

// NewServer returns a new configured server
func NewServer(conf *ServerConfig) *Server {
	ts := Server{
		DoneCh:        make(chan struct{}),
		stopped:       &atomic.Bool{},
		runnerStarted: &atomic.Bool{},

		maxBackoff: conf.MaxBackoff,
		minBackoff: conf.MinBackoff,

		logger:        conf.Logger,
		config:        conf,
		exitAfterAuth: conf.ExitAfterAuth,
	}
	return &ts
}

// Run kicks off the internal Consul Template runner, and listens for changes to
// the token from the AuthHandler. If Done() is called on the context, shut down
// the Runner and return
func (ts *Server) Run(ctx context.Context, incoming chan string, templates []*ctconfig.TemplateConfig) error {
	if incoming == nil {
		return errors.New("template server: incoming channel is nil")
	}

	latestToken := new(string)
	ts.logger.Info("starting template server")

	defer func() {
		ts.logger.Info("template server stopped")
	}()

	// If there are no templates, we wait for context cancellation and then return
	if len(templates) == 0 {
		ts.logger.Info("no templates found")
		<-ctx.Done()
		return nil
	}

	// Prepare backoff mechanism
	if ts.minBackoff <= 0 {
		ts.minBackoff = defaultMinBackoff
	}

	if ts.maxBackoff <= 0 {
		ts.maxBackoff = defaultMaxBackoff
	}

	if ts.minBackoff > ts.maxBackoff {
		return fmt.Errorf("min backoff is larger than max backoff")
	}

	var errBackoff backoff.BackOff = backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(ts.minBackoff),
		backoff.WithMaxInterval(ts.maxBackoff),
		backoff.WithMultiplier(backoffMultiplier),
		backoff.WithRandomizationFactor(backoffRandomizationFactor),
	)

	// If ExitOnRetryFailure is set, disallow retry
	if ts.config.AgentConfig.TemplateConfig != nil && ts.config.AgentConfig.TemplateConfig.ExitOnRetryFailure {
		errBackoff = backoff.WithMaxRetries(errBackoff, 0)
	}

	// timer to time backoffs
	backoffTimer := time.NewTimer(ts.minBackoff)
	defer backoffTimer.Stop()

	// construct a consul template vault config based the agents vault
	// configuration
	var runnerConfig *ctconfig.Config
	var runnerConfigErr error
	managerConfig := ctmanager.ManagerConfig{
		AgentConfig: ts.config.AgentConfig,
		Namespace:   ts.config.Namespace,
		LogLevel:    ts.config.LogLevel,
		LogWriter:   ts.config.LogWriter,
	}
	runnerConfig, runnerConfigErr = ctmanager.NewConfig(managerConfig, templates)
	if runnerConfigErr != nil {
		return fmt.Errorf("template server failed to runner generate config: %w", runnerConfigErr)
	}

	var err error
	ts.runner, err = manager.NewRunner(runnerConfig, false)
	if err != nil {
		return fmt.Errorf("template server failed to create: %w", err)
	}

	// Build the lookup map using the id mapping from the Template runner. This is
	// used to check the template rendering against the expected templates. This
	// returns a map with a generated ID and a slice of templates for that id. The
	// slice is determined by the source or contents of the template, so if a
	// configuration has multiple templates specified, but are the same source /
	// contents, they will be identified by the same key.
	idMap := ts.runner.TemplateConfigMapping()
	lookupMap := make(map[string][]*ctconfig.TemplateConfig, len(idMap))
	for id, ctmpls := range idMap {
		for _, ctmpl := range ctmpls {
			tl := lookupMap[id]
			tl = append(tl, ctmpl)
			lookupMap[id] = tl
		}
	}
	ts.lookupMap = lookupMap

	for {
		select {
		case <-ctx.Done():
			ts.runner.Stop()
			return nil

		case token := <-incoming:
			if token != *latestToken {
				ts.logger.Info("template server received new token")

				// If the runner was previously started and we intend to exit
				// after auth, do not restart the runner if a new token is
				// received.
				if ts.exitAfterAuth && ts.runnerStarted.Load() {
					ts.logger.Info("template server not restarting with new token with exit_after_auth set to true")
					continue
				}

				ts.runner.Stop()
				*latestToken = token
				ctv := ctconfig.Config{
					Vault: &ctconfig.VaultConfig{
						Token:           latestToken,
						ClientUserAgent: pointerutil.StringPtr(useragent.AgentTemplatingString()),
					},
				}

				runnerConfig = runnerConfig.Merge(&ctv)
				var runnerErr error
				ts.runner, runnerErr = manager.NewRunner(runnerConfig, false)
				if runnerErr != nil {
					ts.logger.Error("template server failed with new Vault token", "error", runnerErr)
					continue
				}
				ts.runnerStarted.CompareAndSwap(false, true)
				go ts.runner.Start()
			}

		case err := <-ts.runner.ErrCh:
			nextBackoff := errBackoff.NextBackOff()

			ts.logger.Error("template server error", "error", err.Error(), "backoff", nextBackoff)
			ts.runner.StopImmediately()

			// Return after stopping the runner if backoff indicates stop
			if nextBackoff == backoff.Stop {
				return fmt.Errorf("template server: %w", err)
			}
			// Otherwise back off to retry
			backoffTimer.Reset(nextBackoff)
			select {
			case <-backoffTimer.C:
			case <-ctx.Done():
			}

			ts.runner, err = manager.NewRunner(runnerConfig, false)
			if err != nil {
				return fmt.Errorf("template server failed to create: %w", err)
			}
			go ts.runner.Start()

		case <-ts.runner.TemplateRenderedCh():
			// A template has been rendered, figure out what to do
			events := ts.runner.RenderEvents()

			// Reset backoff for every successfully rendered template
			errBackoff.Reset()

			// events are keyed by template ID, and can be matched up to the id's from
			// the lookupMap
			if len(events) < len(ts.lookupMap) {
				// Not all templates have been rendered yet
				continue
			}

			// assume the renders are finished, until we find otherwise
			doneRendering := true
			for _, event := range events {
				// This template hasn't been rendered
				if event.LastWouldRender.IsZero() {
					doneRendering = false
				}
			}

			if doneRendering && ts.exitAfterAuth {
				// if we want to exit after auth, go ahead and shut down the runner and
				// return. The deferred closing of the DoneCh will allow agent to
				// continue with closing down
				ts.runner.Stop()
				return nil
			}
		}
	}
}

func (ts *Server) Stop() {
	if ts.stopped.CompareAndSwap(false, true) {
		close(ts.DoneCh)
	}
}
