// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"

	"google.golang.org/grpc"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

var (
	_ plugin.Plugin     = (*GRPCBackendPlugin)(nil)
	_ plugin.GRPCPlugin = (*GRPCBackendPlugin)(nil)
)

// GRPCBackendPlugin is the plugin.Plugin implementation that only supports GRPC
// transport
type GRPCBackendPlugin struct {
	Factory      logical.Factory
	MetadataMode bool
	Logger       log.Logger

	MultiplexingSupport bool

	// Embeding this will disable the netRPC protocol
	plugin.NetRPCUnsupportedPlugin
}

func (b GRPCBackendPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	server := backendGRPCPluginServer{
		broker:    broker,
		factory:   b.Factory,
		instances: make(map[string]backendInstance),
		// We pass the logger down into the backend so go-plugin will
		// forward logs for us.
		logger: b.Logger,
	}

	if b.MultiplexingSupport {
		// Multiplexing is enabled for this plugin, register the server so we
		// can tell the client in Vault.
		pluginutil.RegisterPluginMultiplexingServer(s, pluginutil.PluginMultiplexingServerImpl{
			Supported: true,
		})
		server.multiplexingSupport = true
	}

	pb.RegisterBackendServer(s, &server)
	logical.RegisterPluginVersionServer(s, &server)
	return nil
}

func (b *GRPCBackendPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &backendGRPCPluginClient{
		client:        pb.NewBackendClient(c),
		versionClient: logical.NewPluginVersionClient(c),
		broker:        broker,
		cleanupCh:     make(chan struct{}),
		doneCtx:       ctx,
		metadataMode:  b.MetadataMode,
	}, nil
}
