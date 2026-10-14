// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"crypto/tls"
	"math"
	"os"

	"google.golang.org/grpc"

	log "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// BackendPluginName is the name of the plugin that can be
// dispensed from the plugin server.
const BackendPluginName = "backend"

// Deprecated: This will be removed in a future release.
type TLSProviderFunc func() (*tls.Config, error)

type ServeOpts struct {
	BackendFactoryFunc logical.Factory
	Logger             log.Logger

	// Deprecated: This field will be removed in a future release. Plugin
	// authors do not need to set it as OpenBao will establish an mTLS
	// connection to the plugin automatically.
	TLSProviderFunc TLSProviderFunc
}

// Serve is a helper function used to serve a backend plugin. This
// should be ran on the plugin's main process.
func Serve(opts *ServeOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(&log.LoggerOptions{
			Level:      log.Trace,
			Output:     os.Stderr,
			JSONFormat: true,
		})
	}

	// pluginMap is the map of plugins we can dispense.
	pluginSets := map[int]plugin.PluginSet{
		5: {
			"backend": &GRPCBackendPlugin{
				Factory:             opts.BackendFactoryFunc,
				MultiplexingSupport: false,
				Logger:              logger,
			},
		},
	}

	err := pluginutil.OptionallyEnableMlock()
	if err != nil {
		return err
	}

	serveOpts := &plugin.ServeConfig{
		HandshakeConfig:  HandshakeConfig,
		VersionedPlugins: pluginSets,
		Logger:           logger,

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			opts = append(opts, grpc.MaxRecvMsgSize(math.MaxInt32))
			opts = append(opts, grpc.MaxSendMsgSize(math.MaxInt32))
			return plugin.DefaultGRPCServer(opts)
		},
	}

	plugin.Serve(serveOpts)

	return nil
}

// ServeMultiplex is a helper function used to serve a backend plugin. This
// should be ran on the plugin's main process.
func ServeMultiplex(opts *ServeOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = log.New(&log.LoggerOptions{
			Level:      log.Trace,
			Output:     os.Stderr,
			JSONFormat: true,
		})
	}

	// pluginMap is the map of plugins we can dispense.
	pluginSets := map[int]plugin.PluginSet{
		5: {
			"backend": &GRPCBackendPlugin{
				Factory:             opts.BackendFactoryFunc,
				MultiplexingSupport: true,
				Logger:              logger,
			},
		},
	}

	err := pluginutil.OptionallyEnableMlock()
	if err != nil {
		return err
	}

	serveOpts := &plugin.ServeConfig{
		HandshakeConfig:  HandshakeConfig,
		VersionedPlugins: pluginSets,
		Logger:           logger,

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			opts = append(opts, grpc.MaxRecvMsgSize(math.MaxInt32))
			opts = append(opts, grpc.MaxSendMsgSize(math.MaxInt32))
			return plugin.DefaultGRPCServer(opts)
		},
	}

	plugin.Serve(serveOpts)

	return nil
}

// handshakeConfigs are used to just do a basic handshake between
// a plugin and host. If the handshake fails, a user friendly error is shown.
// This prevents users from executing bad plugins or executing a plugin
// directory. It is a UX feature, not a security feature.
var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "VAULT_BACKEND_PLUGIN",
	MagicCookieValue: "6669da05-b1c8-4f49-97d9-c8e5bed98e20",
}
