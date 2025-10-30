// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/openbao/openbao/sdk/v2/helper/docker"
)

func PrepareTestContainer(t *testing.T, version string) (func(), string) {
	env := []string{
		"POSTGRES_PASSWORD=secret",
		"POSTGRES_DB=database",
	}

	_, _, cleanup, url, _ := PrepareTestContainerRaw(t, "postgres", "docker.mirror.hashicorp.services/postgres", version, "secret", true, false, false, env, true, "")

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

	_, _, cleanup, url, _ := PrepareTestContainerRaw(t, "postgres", "docker.mirror.hashicorp.services/postgres", "17", "secret", true, false, false, env, false, "")

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

	runner, _, cleanup, url, id := PrepareTestContainerRaw(t, "postgres", "docker.mirror.hashicorp.services/postgres", version, "secret", true, false, false, env, true, "")

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

	_, _, cleanup, url, _ := PrepareTestContainerRaw(t, "postgres", "docker.mirror.hashicorp.services/postgres", version, password, true, false, false, env, true, "")

	return cleanup, url
}

func PrepareTestContainerRepmgr(t *testing.T, name, version string, envVars []string) (*docker.Runner, func(), string, string) {
	env := append(envVars,
		"REPMGR_PARTNER_NODES=psql-repl-node-0,psql-repl-node-1",
		"REPMGR_PRIMARY_HOST=psql-repl-node-0",
		"REPMGR_PASSWORD=repmgrpass",
		"POSTGRESQL_PASSWORD=secret")

	runner, _, cleanup, url, id := PrepareTestContainerRaw(t, name, "docker.mirror.hashicorp.services/bitnami/postgresql-repmgr", version, "secret", false, true, true, env, true, "")
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

	upCheck := connectPostgres(password, repo)
	if !wait {
		upCheck = connectPostgresNoWait(password, repo)
	}

	svc, containerID, err := runner.StartNewService(context.Background(), addSuffix, forceLocalAddr, upCheck)
	if err != nil {
		t.Fatalf("Could not start docker Postgres: %s", err)
	}

	return runner, svc, svc.Cleanup, svc.Config.URL().String(), containerID
}

func connectPostgres(password, repo string) docker.ServiceAdapter {
	return func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword("postgres", password),
			Host:     fmt.Sprintf("%s:%d", host, port),
			Path:     "postgres",
			RawQuery: "sslmode=disable",
		}

		fmt.Fprintf(os.Stderr, "opening database\n")

		db, err := sql.Open("pgx", u.String())
		if err != nil {
			return nil, err
		}
		defer db.Close()

		if err = db.PingContext(ctx); err != nil {
			return nil, err
		}

		return docker.NewServiceURL(u), nil
	}
}

func connectPostgresNoWait(password, repo string) docker.ServiceAdapter {
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
