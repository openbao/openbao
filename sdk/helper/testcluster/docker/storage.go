// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package docker

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"testing"

	log "github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	dockhelper "github.com/openbao/openbao/sdk/v2/helper/docker"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	thpsql "github.com/openbao/openbao/sdk/v2/helper/testhelpers/postgresql"
)

// InmemStorage configures a test cluster to use the inmem storage backend.
// This avoids waiting for initial Raft leader election or PostgreSQL container
// startup when testing against a single-node cluster, significantly reducing
// test setup time.
type InmemStorage struct{}

func (InmemStorage) Start(context.Context, *testcluster.ClusterOptions) error { return nil }
func (InmemStorage) Cleanup() error                                           { return nil }
func (InmemStorage) Opts() map[string]any {
	return make(map[string]any)
}
func (InmemStorage) Type() string { return "inmem" }

var _ testcluster.NodeStorage = InmemStorage{}

type PostgreSQLStorage struct {
	cleanup     func()
	ExternalUrl string
	InternalUrl string
	Runner      *dockhelper.Runner
	Service     *dockhelper.Service
	Id          string
}

var _ testcluster.NodeStorage = &PostgreSQLStorage{}

// NewPostgreSQLStorage starts the underlying PSQL container and saves its
// connection URL.
func NewPostgreSQLStorage(t *testing.T, network string) *PostgreSQLStorage {
	env := []string{
		"POSTGRES_PASSWORD=secret",
		"POSTGRES_DB=database",
	}

	runner, svc, cleanup, externalUrl, containerID := thpsql.PrepareTestContainerRaw(t, "postgres", "docker.mirror.hashicorp.services/postgres", "latest", "secret", true, false, false, env, false /* don't wait */, network)

	u, err := url.Parse(externalUrl)
	require.NoError(t, err, "failed to parse returned external URL")

	var host string
	if network != "" {
		host = svc.Container.NetworkSettings.Networks[network].IPAddress.String()
	} else {
		for name, info := range svc.Container.NetworkSettings.Networks {
			network = name
			host = info.IPAddress.String()

			t.Logf("found network [%v]: %v", network, info)
		}

		if len(svc.Container.NetworkSettings.Networks) != 1 {
			t.Fatalf("expected only one network if no network name given: %v", network)
		}
	}
	u.Host = fmt.Sprintf("%v:5432", host)

	internalUrl := u.String()

	return &PostgreSQLStorage{
		cleanup:     cleanup,
		ExternalUrl: externalUrl,
		InternalUrl: internalUrl,
		Runner:      runner,
		Service:     svc,
		Id:          containerID,
	}
}

// NewStaticPostgreSQLStorage returns a new PostgreSQLStorage based on static
// connection information without caring where it came from.
func NewStaticPostgreSQLStorage(extConnUrl string, intConnUrl string) *PostgreSQLStorage {
	return &PostgreSQLStorage{
		cleanup:     nil,
		ExternalUrl: extConnUrl,
		InternalUrl: intConnUrl,
	}
}

func (p *PostgreSQLStorage) Start(context.Context, *testcluster.ClusterOptions) error {
	// Initialization already occurred when creating this object.
	return nil
}

func (p *PostgreSQLStorage) Cleanup() error {
	if p.cleanup != nil {
		p.cleanup()
	}
	return nil
}

func (p *PostgreSQLStorage) Opts() map[string]any {
	return map[string]any{
		"connection_url":       p.InternalUrl,
		"ha_enabled":           true,
		"max_parallel":         5,
		"max_idle_connections": 3,
		"max_connect_retries":  30,
	}
}

func (p *PostgreSQLStorage) Type() string {
	return "postgresql"
}

func (p *PostgreSQLStorage) Client(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("pgx", p.ExternalUrl)
	if err != nil {
		return nil, err
	}

	if err = db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

type PostgreSQLClusterMapper func(ctx context.Context, cluster *thpsql.Cluster, index int) (*thpsql.Node, error)

type PostgreSQLClusterStorage struct {
	Cluster *thpsql.Cluster
	mapper  PostgreSQLClusterMapper
}

var _ testcluster.ClusterStorage = &PostgreSQLClusterStorage{}

func NewPostgreSQLClusterStorage(ctx context.Context, logger log.Logger, name string, network string, mapper PostgreSQLClusterMapper) (*PostgreSQLClusterStorage, error) {
	cfg := thpsql.DefaultClusterConfig(name)
	if logger != nil {
		cfg.Logger = logger
	}

	cluster, err := cfg.NewCluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to set up cluster: %w", err)
	}

	return &PostgreSQLClusterStorage{
		Cluster: cluster,
		mapper:  mapper,
	}, nil
}

func (p *PostgreSQLClusterStorage) Cleanup() error {
	p.Cluster.Cleanup()
	return nil
}

func (p *PostgreSQLClusterStorage) Type() string {
	return "postgresql"
}

func (p *PostgreSQLClusterStorage) ForNode(ctx context.Context, index int) (testcluster.NodeStorage, error) {
	pNode, err := p.mapper(ctx, p.Cluster, index)
	if err != nil {
		return nil, fmt.Errorf("error invoking mapper(ctx, cluster, %d): %w", index, err)
	}

	extUrl := pNode.ConnectionURL
	intUrl, err := pNode.InternalURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting internal URL for node %d->%v: %w", index, pNode.ContainerID, err)
	}

	return NewStaticPostgreSQLStorage(extUrl, intUrl), nil
}
