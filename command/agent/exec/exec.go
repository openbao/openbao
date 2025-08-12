package exec

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao-template/child"
	ctconfig "github.com/openbao/openbao-template/config"
	"github.com/openbao/openbao-template/manager"
	"golang.org/x/exp/slices"

	"github.com/openbao/openbao/command/agent/config"
	"github.com/openbao/openbao/command/agent/internal/ctmanager"
	"github.com/openbao/openbao/helper/useragent"
	"github.com/openbao/openbao/sdk/v2/helper/pointerutil"
)

type childProcessState uint8

const (
	childProcessStateNotStarted childProcessState = iota
	childProcessStateRunning
	childProcessStateRestarting
	childProcessStateStopped
)

type ServerConfig struct {
	Logger      hclog.Logger
	AgentConfig *config.Config

	Namespace string

	// LogLevel is needed to set the internal Consul Template Runner's log level
	// to match the log level of Vault Agent. The internal Runner creates it's own
	// logger and can't be set externally or copied from the Template Server.
	//
	// LogWriter is needed to initialize Consul Template's internal logger to use
	// the same io.Writer that Vault Agent itself is using.
	LogLevel  hclog.Level
	LogWriter io.Writer
}

type Server struct {
	// config holds the ServerConfig used to create it. It's passed along in other
	// methods
	config *ServerConfig

	// runner is the consul-template runner
	runner *manager.Runner

	// numberOfTemplates is the count of templates determined by consul-template,
	// we keep the value to ensure all templates have been rendered before
	// starting the child process
	// NOTE: each template may have more than one TemplateConfig, so the numbers may not match up
	numberOfTemplates int

	logger hclog.Logger

	childProcess      *child.Child
	childProcessState childProcessState
	childProcessLock  sync.Mutex

	// exit channel of the child process
	childProcessExitCh chan int

	// lastRenderedEnvVars is the cached value of all environment variables
	// rendered by the templating engine; it is used for detecting changes
	lastRenderedEnvVars []string
}

type ProcessExitError struct {
	ExitCode int
}

func (e *ProcessExitError) Error() string {
	return fmt.Sprintf("process exited with %d", e.ExitCode)
}

func NewServer(cfg *ServerConfig) *Server {
	server := Server{
		logger:             cfg.Logger,
		config:             cfg,
		childProcessState:  childProcessStateNotStarted,
		childProcessExitCh: make(chan int),
	}

	return &server
}

func (s *Server) Run(ctx context.Context, incomingVaultToken chan string) error {
	latestToken := new(string)
	s.logger.Info("starting exec server")
	defer func() {
		s.logger.Info("exec server stopped")
	}()

	if len(s.config.AgentConfig.EnvTemplates) == 0 || s.config.AgentConfig.Exec == nil {
		s.logger.Info("no env templates or exec config, exiting")
		<-ctx.Done()
		return nil
	}

	managerConfig := ctmanager.ManagerConfig{
		AgentConfig: s.config.AgentConfig,
		Namespace:   s.config.Namespace,
		LogLevel:    s.config.LogLevel,
		LogWriter:   s.config.LogWriter,
	}

	runnerConfig, err := ctmanager.NewConfig(managerConfig, s.config.AgentConfig.EnvTemplates)
	if err != nil {
		return fmt.Errorf("template server failed to generate runner config: %w", err)
	}

	// We leave this in "dry" mode, as there are no files to render;
	// we will get the environment variables rendered contents from the incoming events
	s.runner, err = manager.NewRunner(runnerConfig, true)
	if err != nil {
		return fmt.Errorf("template server failed to create: %w", err)
	}

	// prevent the templates from being rendered to stdout in "dry" mode
	s.runner.SetOutStream(io.Discard)

	s.numberOfTemplates = len(s.runner.TemplateConfigMapping())

	// We receive multiple events every staticSecretRenderInterval
	// from <-s.runner.TemplateRenderedCh(), one for each secret. Only the last
	// event in a batch will contain the latest set of all secrets and the
	// corresponding environment variables. This timer will fire after 2 seconds
	// unless an event comes in which resets the timer back to 2 seconds.
	var debounceTimer *time.Timer

	// capture the errors related to restarting the child process
	restartChildProcessErrCh := make(chan error)

	for {
		select {
		case <-ctx.Done():
			s.runner.Stop()
			s.childProcessLock.Lock()
			if s.childProcess != nil {
				s.childProcess.Stop()
			}
			s.childProcessState = childProcessStateStopped
			s.childProcessLock.Unlock()
			return nil

		case token := <-incomingVaultToken:
			if token != *latestToken {
				s.logger.Info("exec server received new token")

				s.runner.Stop()
				*latestToken = token
				newTokenConfig := ctconfig.Config{
					Vault: &ctconfig.VaultConfig{
						Token:           latestToken,
						ClientUserAgent: pointerutil.StringPtr(useragent.AgentTemplatingString()),
					},
				}

				// got a new auth token, merge it in with the existing config
				runnerConfig = runnerConfig.Merge(&newTokenConfig)
				s.runner, err = manager.NewRunner(runnerConfig, true)
				if err != nil {
					s.logger.Error("template server failed with new Vault token", "error", err)
					continue
				}

				// prevent the templates from being rendered to stdout in "dry" mode
				s.runner.SetOutStream(io.Discard)

				go s.runner.Start()
			}

		case err := <-s.runner.ErrCh:
			s.logger.Error("template server error", "error", err.Error())
			s.runner.StopImmediately()

			// Return after stopping the runner if exit on retry failure was specified
			if s.config.AgentConfig.TemplateConfig != nil && s.config.AgentConfig.TemplateConfig.ExitOnRetryFailure {
				return fmt.Errorf("template server: %w", err)
			}

			s.runner, err = manager.NewRunner(runnerConfig, true)
			if err != nil {
				return fmt.Errorf("template server failed to create: %w", err)
			}
			go s.runner.Start()

		case <-s.runner.TemplateRenderedCh():
			// A template has been rendered, figure out what to do
			s.logger.Trace("template rendered")
			events := s.runner.RenderEvents()

			// This checks if we've finished rendering the initial set of templates,
			// for every consecutive re-render len(events) should equal s.numberOfTemplates
			if len(events) < s.numberOfTemplates {
				// Not all templates have been rendered yet
				continue
			}

			// assume the renders are finished, until we find otherwise
			doneRendering := true
			var renderedEnvVars []string
			for _, event := range events {
				// This template hasn't been rendered
				if event.LastWouldRender.IsZero() {
					doneRendering = false
					break
				} else {
					for _, tcfg := range event.TemplateConfigs {
						envVar := fmt.Sprintf("%s=%s", *tcfg.MapToEnvironmentVariable, event.Contents)
						renderedEnvVars = append(renderedEnvVars, envVar)
					}
				}
			}
			if !doneRendering {
				continue
			}

			// sort the environment variables for a deterministic output and easy comparison
			sort.Strings(renderedEnvVars)

			s.logger.Trace("done rendering templates")

			// don't restart the process unless a change is detected
			if slices.Equal(s.lastRenderedEnvVars, renderedEnvVars) {
				continue
			}

			s.lastRenderedEnvVars = renderedEnvVars

			s.logger.Debug("detected a change in the environment variables: restarting the child process")

			// if a timer exists, stop it
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(2*time.Second, func() {
				if err := s.restartChildProcess(renderedEnvVars); err != nil {
					restartChildProcessErrCh <- fmt.Errorf("unable to restart the child process: %w", err)
				}
			})

		case err := <-restartChildProcessErrCh:
			// catch the error from restarting
			return err

		case exitCode := <-s.childProcessExitCh:
			// process exited on its own
			return &ProcessExitError{ExitCode: exitCode}
		}
	}
}

func (s *Server) restartChildProcess(newEnvVars []string) error {
	s.childProcessLock.Lock()
	defer s.childProcessLock.Unlock()

	switch s.config.AgentConfig.Exec.RestartOnSecretChanges {
	case "always":
		if s.childProcessState == childProcessStateRunning {
			// process is running, need to kill it first
			s.logger.Info("stopping process", "process_id", s.childProcess.Pid())
			s.childProcessState = childProcessStateRestarting
			s.childProcess.Stop()
		}
	case "never":
		if s.childProcessState == childProcessStateRunning {
			s.logger.Info("detected update, but not restarting process", "process_id", s.childProcess.Pid())
			return nil
		}
	default:
		return fmt.Errorf("invalid value for restart-on-secret-changes: %q", s.config.AgentConfig.Exec.RestartOnSecretChanges)
	}

	args, subshell, err := child.CommandPrep(s.config.AgentConfig.Exec.Command)
	if err != nil {
		return fmt.Errorf("unable to parse command: %w", err)
	}

	childInput := &child.NewInput{
		Stdin:        os.Stdin,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		Command:      args[0],
		Args:         args[1:],
		Timeout:      0, // let it run forever
		Env:          append(os.Environ(), newEnvVars...),
		ReloadSignal: nil, // can't reload w/ new env vars
		KillSignal:   s.config.AgentConfig.Exec.RestartStopSignal,
		KillTimeout:  30 * time.Second,
		Splay:        0,
		Setpgid:      subshell,
		Logger:       s.logger.StandardLogger(nil),
	}

	proc, err := child.New(childInput)
	if err != nil {
		return err
	}
	s.childProcess = proc

	if err := s.childProcess.Start(); err != nil {
		return fmt.Errorf("error starting the child process: %w", err)
	}

	s.childProcessState = childProcessStateRunning

	// Listen if the child process exits and bubble it up to the main loop.
	//
	// NOTE: this must be invoked after child.Start() to avoid a potential
	// race condition with ExitCh not being initialized.
	go func() {
		exitCode, ok := <-proc.ExitCh()
		if ok {
			s.childProcessExitCh <- exitCode
		}
	}()

	return nil
}
