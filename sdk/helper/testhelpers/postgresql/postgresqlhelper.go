// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/containerd/errdefs"
	log "github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/moby/moby/client"

	"github.com/openbao/openbao/sdk/v2/helper/docker"
)

const (
	DefaultPSQLRepo   = "docker.mirror.hashicorp.services/postgres"
	DefaultRepmgrRepo = "docker.mirror.hashicorp.services/bitnami/postgresql-repmgr"
)

func PrepareTestContainer(t *testing.T, version string) (func(), string) {
	env := []string{
		"POSTGRES_PASSWORD=secret",
		"POSTGRES_DB=database",
	}

	_, _, cleanup, url, _ := PrepareTestContainerRaw(t, "postgres", DefaultPSQLRepo, version, "secret", true, false, false, env, true, "")

	return cleanup, url
}

// TestContainerNoWait creates a PostgreSQL container but does not wait for
// PostgreSQL to be ready for requests; this is useful when testing retry
// logic in the container handler.
func TestContainerNoWait(t *testing.T) (func(), string) {
	env := []string{
		"POSTGRES_PASSWORD=secret",
		"POSTGRES_DB=database",
	}

	_, _, cleanup, url, _ := PrepareTestContainerRaw(t, "postgres", DefaultPSQLRepo, "17", "secret", true, false, false, env, false, "")

	return cleanup, url
}

// PrepareTestContainerWithVaultUser will setup a test container with a Vault
// admin user configured so that we can safely call rotate-root without
// rotating the root DB credentials
func PrepareTestContainerWithVaultUser(t *testing.T, ctx context.Context, version string) (func(), string) {
	env := []string{
		"POSTGRES_PASSWORD=secret",
		"POSTGRES_DB=database",
	}

	runner, _, cleanup, url, id := PrepareTestContainerRaw(t, "postgres", DefaultPSQLRepo, version, "secret", true, false, false, env, true, "")

	cmd := []string{"psql", "-U", "postgres", "-c", "CREATE USER vaultadmin WITH LOGIN PASSWORD 'vaultpass' SUPERUSER"}
	_, err := runner.RunCmdInBackground(ctx, id, cmd)
	if err != nil {
		t.Fatalf("Could not run command (%v) in container: %v", cmd, err)
	}

	return cleanup, url
}

func PrepareTestContainerWithPassword(t *testing.T, version, password string) (func(), string) {
	env := []string{
		"POSTGRES_PASSWORD=" + password,
		"POSTGRES_DB=database",
	}

	_, _, cleanup, url, _ := PrepareTestContainerRaw(t, "postgres", DefaultPSQLRepo, version, password, true, false, false, env, true, "")

	return cleanup, url
}

func PrepareTestContainerRepmgr(t *testing.T, name, version string, envVars []string) (*docker.Runner, func(), string, string) {
	env := append(envVars,
		"REPMGR_PARTNER_NODES=psql-repl-node-0,psql-repl-node-1",
		"REPMGR_PRIMARY_HOST=psql-repl-node-0",
		"REPMGR_PASSWORD=repmgrpass",
		"POSTGRESQL_PASSWORD=secret")

	runner, _, cleanup, url, id := PrepareTestContainerRaw(t, name, DefaultRepmgrRepo, version, "secret", false, true, true, env, true, "")
	return runner, cleanup, url, id
}

func PrepareTestContainerRaw(t *testing.T, name, repo, version, password string,
	addSuffix, forceLocalAddr, doNotAutoRemove bool, envVars []string, wait bool,
	network string,
) (*docker.Runner, *docker.Service, func(), string, string) {
	if os.Getenv("PG_URL") != "" {
		return nil, nil, func() {}, "", os.Getenv("PG_URL")
	}

	if version == "" {
		version = "17"
	}

	runOpts := docker.RunOptions{
		ContainerName:   name,
		ImageRepo:       repo,
		ImageTag:        version,
		Env:             envVars,
		Ports:           []string{"5432/tcp"},
		DoNotAutoRemove: doNotAutoRemove,
		NetworkName:     network,
	}
	if repo == "bitnami/postgresql-repmgr" {
		runOpts.NetworkID = os.Getenv("POSTGRES_MULTIHOST_NET")
	}

	runner, err := docker.NewServiceRunner(runOpts)
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	upCheck := connectPostgres(password)
	if !wait {
		upCheck = connectPostgresNoWait(password)
	}

	svc, containerID, err := runner.StartNewService(t.Context(), addSuffix, forceLocalAddr, upCheck)
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	return runner, svc, svc.Cleanup, svc.Config.URL().String(), containerID
}

func connectPostgres(password string) docker.ServiceAdapter {
	return func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword("postgres", password),
			Host:     fmt.Sprintf("%s:%d", host, port),
			Path:     "postgres",
			RawQuery: "sslmode=disable",
		}

		fmt.Fprintf(os.Stderr, "opening database: %v\n", u.String())

		db, err := sql.Open("pgx", u.String())
		if err != nil {
			return nil, err
		}
		defer db.Close() //nolint:errcheck

		if err = db.PingContext(ctx); err != nil {
			return nil, err
		}

		return docker.NewServiceURL(u), nil
	}
}

func connectPostgresNoWait(password string) docker.ServiceAdapter {
	return func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword("postgres", password),
			Host:     fmt.Sprintf("%s:%d", host, port),
			Path:     "postgres",
			RawQuery: "sslmode=disable",
		}

		return docker.NewServiceURL(u), nil
	}
}

func StopContainer(t *testing.T, ctx context.Context, runner *docker.Runner, containerID string) {
	if err := runner.Stop(ctx, containerID); err != nil {
		t.Fatalf("Could not stop docker Postgres: %s", err)
	}
}

func RestartContainer(t *testing.T, ctx context.Context, runner *docker.Runner, containerID string) {
	if err := runner.Restart(ctx, containerID); err != nil {
		t.Fatalf("Could not restart docker Postgres: %s", err)
	}
}

type ClusterConfig struct {
	Name      string
	AddSuffix bool

	Repo    string
	Version string

	Password        string
	DoNotAutoRemove bool

	WALLevel string
	EnvVars  []string

	Logger log.Logger
}

func DefaultClusterConfig(name string) *ClusterConfig {
	return &ClusterConfig{
		Name:            name,
		AddSuffix:       true,
		Repo:            DefaultPSQLRepo,
		Version:         "17",
		Password:        "secret",
		DoNotAutoRemove: true,
		WALLevel:        "replica",
		EnvVars: []string{
			"POSTGRES_DB=database",
		},
		Logger: log.NewNullLogger(),
	}
}

type Cluster struct {
	Config *ClusterConfig

	Primary *Node
	Nodes   []*Node

	Network string
}

type Node struct {
	Runner        *docker.Runner
	Service       *docker.Service
	ConnectionURL string
	ContainerID   string
}

// NewCluster sets up the cluster and adds the initial node.
func (c *ClusterConfig) NewCluster(ctx context.Context) (*Cluster, error) {
	cluster := &Cluster{
		Config: c,
	}

	primary, err := cluster.addPrimary(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to add primary node: %w", err)
	}
	cluster.Primary = primary
	cluster.Nodes = append(cluster.Nodes, primary)

	cluster.Network, err = primary.Network()
	if err != nil {
		return nil, fmt.Errorf("failed to check network: %w", err)
	}

	return cluster, err
}

func (c *Cluster) Cleanup() {
	c.CleanupWithContext(context.Background())
}

func (c *Cluster) CleanupWithContext(ctx context.Context) {
	if c == nil {
		return
	}

	c.Primary.Cleanup()
	for _, node := range c.Nodes {
		node.Cleanup()
	}
}

func (c *Cluster) env() []string {
	env := make([]string, len(c.Config.EnvVars)+1)
	env[0] = "POSTGRES_PASSWORD=" + c.Config.Password
	copy(env[1:], c.Config.EnvVars)
	return env
}

func (c *Cluster) primaryCmd() []string {
	return []string{
		"postgres",
		"-cwal_level=" + c.Config.WALLevel,
		"-chot_standby=on",
		"-cmax_wal_senders=10",
		"-cmax_replication_slots=10",
		"-chot_standby_feedback=on",
	}
}

func (c *Cluster) runOpts(node string) docker.RunOptions {
	return docker.RunOptions{
		ContainerName:   fmt.Sprintf("%v-%v", c.Config.Name, node),
		ImageRepo:       c.Config.Repo,
		ImageTag:        c.Config.Version,
		Env:             c.env(),
		Ports:           []string{"5432/tcp"},
		DoNotAutoRemove: c.Config.DoNotAutoRemove,
		NetworkName:     c.Network,
		WriteInto:       map[string]docker.BuildContext{},
	}
}

func (c *Cluster) primaryInit() string {
	// See https://sadeesha.medium.com/building-a-postgresql-replication-cluster-with-docker-compose-45406078de72
	script := `#!/bin/bash

set -euxo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
 CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD '` + c.Config.Password + `';
EOSQL

# Allow replication connections from any host in the Docker network
echo "host replication replicator 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"

# Reload PostgreSQL configuration
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -c "SELECT pg_reload_conf();"
  `

	return script
}

func (c *Cluster) addPrimary(ctx context.Context) (*Node, error) {
	c.Config.Logger.Debug("starting primary")
	node := &Node{}

	runOpts := c.runOpts("primary")
	runOpts.WriteInto["/docker-entrypoint-initdb.d"] = docker.NewBuildContext()
	runOpts.WriteInto["/docker-entrypoint-initdb.d"]["init-primary.sh"] = docker.PathContentsFromString(c.primaryInit())

	runOpts.Cmd = c.primaryCmd()

	runner, err := docker.NewServiceRunner(runOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create runner for primary node: %w", err)
	}

	upCheck := connectPostgres(c.Config.Password)
	svc, containerID, err := runner.StartNewService(ctx, c.Config.AddSuffix, true, upCheck)
	if err != nil {
		return nil, fmt.Errorf("could not start primary node: %w", err)
	}

	node.Runner = runner
	node.Service = svc
	node.ConnectionURL = svc.Config.URL().String()
	node.ContainerID = containerID

	return node, err
}

func (c *Cluster) addReplica(ctx context.Context) (*Node, error) {
	c.Config.Logger.Debug("adding replica")

	// Take the primary node, connect to it, and add a new replication slot.
	db, err := c.Primary.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary's client: %w", err)
	}
	defer db.Close() //nolint:errcheck

	slot := len(c.Nodes)

	_, err = db.Exec(fmt.Sprintf("SELECT * FROM pg_create_physical_replication_slot('replication_slot_%d');", slot))
	if err != nil {
		return nil, fmt.Errorf("failed add new replication slot %v: %w", slot, err)
	}

	host, err := c.Primary.NetworkIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary's network IP address: %w", err)
	}

	script := `
pg_ctl stop -D /var/lib/postgresql/data

rm -rf /var/lib/postgresql/data/*

until PGPASSWORD=` + c.Config.Password + ` pg_basebackup -h ` + host + ` -U replicator -D /var/lib/postgresql/data -R -X stream -c fast -S replication_slot_` + strconv.Itoa(slot) + `; do
	echo "Waiting for primary..."
	sleep 2
done

echo "primary_conninfo = 'host=` + host + ` port=5432 user=replicator password=` + c.Config.Password + `'" >> /var/lib/postgresql/data/postgresql.conf

touch /var/lib/postgresql/data/standby.signal

pg_ctl start -D /var/lib/postgresql/data

docker-entrypoint.sh postgres
`

	runOpts := c.runOpts(fmt.Sprintf("replica_%v", slot))
	runOpts.Entrypoint = []string{"bash", "-c", script}
	runOpts.NetworkID = c.Network

	runner, err := docker.NewServiceRunner(runOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create replica %d's service runner: %w", slot, err)
	}

	upCheck := connectPostgres(c.Config.Password)
	svc, containerID, err := runner.StartNewService(ctx, c.Config.AddSuffix, true, upCheck)
	if err != nil {
		return nil, fmt.Errorf("failed to start replica %d: %w", slot, err)
	}

	return &Node{
		Runner:        runner,
		Service:       svc,
		ConnectionURL: svc.Config.URL().String(),
		ContainerID:   containerID,
	}, nil
}

func (c *Cluster) AddNode(ctx context.Context) (*Node, error) {
	replica, err := c.addReplica(ctx)
	if err != nil {
		return nil, err
	}

	c.Nodes = append(c.Nodes, replica)
	return replica, nil
}

func (c *Cluster) RemovePrimary(ctx context.Context) error {
	primary := c.Primary

	_, err := primary.Runner.DockerAPI.ContainerRemove(ctx, primary.ContainerID, client.ContainerRemoveOptions{Force: true})
	if err != nil && errdefs.IsNotFound(err) {
		return fmt.Errorf("failed to kill primary: %w", err)
	}

	defer primary.Cleanup()

	c.Primary = nil

	idx := -1
	for index, node := range c.Nodes {
		if node == primary {
			idx = index
			break
		}
	}

	if idx != -1 {
		c.Nodes = append(c.Nodes[0:idx], c.Nodes[idx+1:]...)
	}

	return nil
}

func (c *Cluster) PromoteNode(ctx context.Context, index int) error {
	if index < 0 || index >= len(c.Nodes) {
		return fmt.Errorf("index %v out of bounds: %v nodes", index, len(c.Nodes))
	}
	if len(c.Nodes) != 1 {
		return fmt.Errorf("have %v nodes but can only promote with one right now", len(c.Nodes))
	}

	node := c.Nodes[index]

	db, err := node.Client(ctx)
	if err != nil {
		return fmt.Errorf("failed getting node's client: %w", err)
	}
	defer db.Close() //nolint:errcheck

	var inRecovery bool
	if err := db.QueryRowContext(ctx, "SELECT pg_is_in_recovery();").Scan(&inRecovery); err != nil {
		return fmt.Errorf("failed to read recovery mode status: %w", err)
	}

	if !inRecovery {
		return fmt.Errorf("cannot promote node with pg_is_in_recovery()=%v", inRecovery)
	}

	_, err = db.ExecContext(ctx, "SELECT pg_promote();")
	if err != nil {
		return fmt.Errorf("failed to promote node: %w", err)
	}

	c.Primary = node
	return nil
}

func (n *Node) Cleanup() {
	if n == nil || n.Service == nil {
		return
	}

	n.Service.Cleanup()
}

func (n *Node) Network() (string, error) {
	networks, err := n.Runner.GetNetworkAndAddresses(n.ContainerID)
	if err != nil {
		return "", fmt.Errorf("failed to get network addresses: %w", err)
	}

	if len(networks) != 1 {
		return "", fmt.Errorf("expected only a single network: %#v", networks)
	}

	for name := range networks {
		return name, nil
	}

	return "", errors.New("unknown failure?")
}

func (n *Node) NetworkIP(ctx context.Context) (string, error) {
	inspect, err := n.Runner.DockerAPI.ContainerInspect(ctx, n.ContainerID, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %v: %w", n.ContainerID, err)
	}

	network, err := n.Network()
	if err != nil {
		return "", fmt.Errorf("failed to get network for primary container: %w", err)
	}

	if _, ok := inspect.Container.NetworkSettings.Networks[network]; !ok {
		return "", fmt.Errorf("network %v not in container %v's networks list: %#v", network, n.ContainerID, inspect.Container.NetworkSettings.Networks)
	}

	info := inspect.Container.NetworkSettings.Networks[network]
	return info.IPAddress.String(), nil
}

func (n *Node) InternalURL(ctx context.Context) (string, error) {
	u, err := url.Parse(n.ConnectionURL)
	if err != nil {
		return "", fmt.Errorf("unable to parse connection URL: %w", err)
	}

	host, err := n.NetworkIP(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to get node's network IP address: %w", err)
	}

	u.Host = fmt.Sprintf("%v:5432", host)
	return u.String(), nil
}

func (n *Node) Client(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("pgx", n.ConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify database was working: %w", err)
	}

	return db, nil
}
