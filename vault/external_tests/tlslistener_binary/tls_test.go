package tlslistener_binary

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/builtin/logical/pki/dnstest"
	hDocker "github.com/openbao/openbao/sdk/v2/helper/docker"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"

	"github.com/stretchr/testify/require"
)

func entrypointPath(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Logf("failed to infer path to docker entrypoint; making assuption")
		return ".release/docker/docker-entrypoint.sh"
	}

	return filepath.Join(filepath.Dir(file), "../../../", ".release/docker/docker-entrypoint.sh")
}

func TestTLSListener_SelfHostedNonStandard(t *testing.T) {
	// We provision OpenBao in a container so that we can simulate
	// having remote-only access with ACME over non-TLS localhost only.
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running docker test when $BAO_BINARY present")
	}

	opts := &docker.DockerClusterOptions{
		ImageRepo: "quay.io/openbao/openbao",
		// We're replacing the binary anyway, so we're not too particular about
		// the docker image version tag.
		ImageTag:    "latest",
		VaultBinary: binary,

		// We need root here to temporarily bind to port 80.
		Root:       true,
		Entrypoint: entrypointPath(t),
		ClusterOptions: testcluster.ClusterOptions{
			NumCores: 1,
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
				// We add two additional listeners: a HTTP-only listener and
				// one with ACME TLS enabled.
				AdditionalListeners: []interface{}{
					map[string]interface{}{
						"tcp": map[string]interface{}{
							"address":     "0.0.0.0:8300",
							"tls_disable": true,
						},
					},
					map[string]interface{}{
						"tcp": map[string]interface{}{
							"address":               "0.0.0.0:8400",
							"tls_acme_cache_path":   "/tmp",
							"tls_acme_ca_directory": "http://127.0.0.1:8300/v1/pki/acme/directory",
						},
					},
				},
			},
		},
	}

	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	node, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err, "failed to get active node")
	require.NotNil(t, node)

	client := cluster.ClusterNodes[node].APIClient()
	require.NotNil(t, client)

	// Configure PKI mount for self-hosting ACME.
	root := setupPki(t, client, ":8300")

	// Validate ACME cert acquisition works.
	validateTLS(t, ctx, root, cluster.ClusterNodes[node].ContainerNetworkName, cluster.ClusterNodes[node].ContainerIPAddress+":8400", "", false)
}

func TestTLSListener_SelfHostedPrivileged(t *testing.T) {
	// We provision OpenBao in a container so that we can simulate
	// having remote-only access with ACME over non-TLS localhost only.
	//
	// This differs from the above in that we provision port 80 and 443
	// listeners, on standard, privileged ports. The above will automatically
	// create a short-term port 80 listener just to solve the HTTP challenge.
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running docker test when $BAO_BINARY present")
	}

	opts := &docker.DockerClusterOptions{
		ImageRepo: "quay.io/openbao/openbao",
		// We're replacing the binary anyway, so we're not too particular about
		// the docker image version tag.
		ImageTag:    "latest",
		VaultBinary: binary,
		Root:        true,
		Entrypoint:  entrypointPath(t),
		ClusterOptions: testcluster.ClusterOptions{
			NumCores: 1,
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
				// We add two additional listeners: a HTTP-only listener and
				// one with ACME TLS enabled.
				AdditionalListeners: []interface{}{
					map[string]interface{}{
						"tcp": map[string]interface{}{
							"address":     "0.0.0.0:80",
							"tls_disable": true,
						},
					},
					map[string]interface{}{
						"tcp": map[string]interface{}{
							"address":               "0.0.0.0:443",
							"tls_acme_cache_path":   "/tmp",
							"tls_acme_ca_directory": "http://127.0.0.1:80/v1/pki/acme/directory",
						},
					},
				},
			},
		},
	}

	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	node, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err, "failed to get active node")
	require.NotNil(t, node)

	client := cluster.ClusterNodes[node].APIClient()
	require.NotNil(t, client)

	// Configure PKI mount for self-hosting ACME.
	root := setupPki(t, client, ":80")

	// Validate ACME cert acquisition works.
	validateTLS(t, ctx, root, cluster.ClusterNodes[node].ContainerNetworkName, cluster.ClusterNodes[node].ContainerIPAddress+":443", "", false)
}

func TestTLSListener_ALPN(t *testing.T) {
	// We provision OpenBao in a container so that we can simulate
	// using DNS and ALPN (which must be solved via port 443).
	//
	// This is also used to test our deny list capabilities.
	binary := api.ReadBaoVariable("BAO_BINARY")
	if binary == "" {
		t.Skip("only running docker test when $BAO_BINARY present")
	}

	opts := &docker.DockerClusterOptions{
		ImageRepo: "quay.io/openbao/openbao",
		// We're replacing the binary anyway, so we're not too particular about
		// the docker image version tag.
		ImageTag:    "latest",
		VaultBinary: binary,
		Root:        true,
		Entrypoint:  entrypointPath(t),
		ClusterOptions: testcluster.ClusterOptions{
			NumCores: 1,
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
				// We add two additional listeners: a HTTP-only listener and
				// one with ACME TLS enabled.
				AdditionalListeners: []interface{}{
					map[string]interface{}{
						"tcp": map[string]interface{}{
							"address":     "0.0.0.0:80",
							"tls_disable": true,
						},
					},
					map[string]interface{}{
						"tcp": map[string]interface{}{
							"address":                         "0.0.0.0:443",
							"tls_acme_cache_path":             "/tmp",
							"tls_acme_ca_directory":           "http://127.0.0.1:80/v1/pki/acme/directory",
							"tls_acme_disable_http_challenge": true,
							"tls_acme_domains":                []string{"openbao.dadgarcorp.com"},
						},
					},
				},
			},
		},
	}

	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	node, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err, "failed to get active node")
	require.NotNil(t, node)

	client := cluster.ClusterNodes[node].APIClient()
	require.NotNil(t, client)

	// Configure PKI mount for self-hosting ACME.
	root := setupPki(t, client, ":80")

	dns := dnstest.SetupResolverOnNetwork(t, "dadgarcorp.com", cluster.ClusterNodes[node].ContainerNetworkName)
	defer dns.Cleanup()

	// Set hostname for the container.
	dns.AddRecord("openbao.dadgarcorp.com", "A", cluster.ClusterNodes[node].ContainerIPAddress)
	dns.AddRecord("invalid.dadgarcorp.com", "A", cluster.ClusterNodes[node].ContainerIPAddress)
	dns.PushConfig()

	client.Logical().Write("pki/config/acme", map[string]interface{}{
		"enabled":      true,
		"dns_resolver": dns.GetRemoteAddr(),
	})

	// Validate ACME cert acquisition works.
	validateTLS(t, ctx, root, cluster.ClusterNodes[node].ContainerNetworkName, "openbao.dadgarcorp.com:443", dns.GetRemoteAddr(), false)
	validateTLS(t, ctx, root, cluster.ClusterNodes[node].ContainerNetworkName, "invalid.dadgarcorp.com:443", dns.GetRemoteAddr(), true)
}

func setupPki(t *testing.T, client *api.Client, acmePort string) string {
	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
			AllowedResponseHeaders: []string{
				"Last-Modified", "Replay-Nonce",
				"Link", "Location",
			},
		},
	})
	require.NoError(t, err)

	defaultPath := "http://127.0.0.1" + acmePort + "/v1/pki"
	config := map[string]interface{}{
		"path":     defaultPath,
		"aia_path": defaultPath,
	}

	_, err = client.Logical().Write("pki/config/cluster", config)
	require.NoError(t, err)

	_, err = client.Logical().Write("pki/config/acme", map[string]interface{}{
		"enabled": true,
	})
	require.NoError(t, err)

	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"common_name": "Root R1",
		"key_type":    "ec",
		"issuer_name": "root",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)

	return resp.Data["certificate"].(string)
}

func validateTLS(t *testing.T, ctx context.Context, root string, networkName string, address string, dnsAddr string, expectFail bool) {
	// Since the cluster is unsealed and functional, we can attempt a request
	// on the desired address to get a working certificate. We need to bind
	// another container to the same network; using local Go here will result
	// in a certificate with the container network's IP address rather than
	// localhost.
	containerfile := `
FROM ubuntu:latest

RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y curl

COPY root.pem /root.pem
`

	bCtx := hDocker.NewBuildContext()
	bCtx["root.pem"] = &hDocker.FileContents{
		Data: []byte(root),
		Mode: 0o755,
	}

	imageName := "openbao_acme_tls_curl_integration"
	imageTag := "latest"

	cRunner, err := hDocker.NewServiceRunner(hDocker.RunOptions{
		ImageRepo:     imageName,
		ImageTag:      imageTag,
		ContainerName: "openbao_acme_tls_curl",
		NetworkName:   networkName,
		// We want to run sleep in the background so we're not stuck waiting
		// for the default ubuntu container's shell to prompt for input.
		Entrypoint: []string{"sleep", "45"},
		LogConsumer: func(s string) {
			if t.Failed() {
				t.Logf("container logs: %s", s)
			}
		},
	})
	if err != nil {
		t.Fatalf("Could not provision docker service runner: %s", err)
	}

	output, err := cRunner.BuildImage(ctx, containerfile, bCtx,
		hDocker.BuildRemove(true), hDocker.BuildForceRemove(true),
		hDocker.BuildPullParent(true),
		hDocker.BuildTags([]string{imageName + ":" + imageTag}))
	if err != nil {
		t.Fatalf("Could not build new image: %v", err)
	}

	t.Logf("Image build output: %v", string(output))

	result, err := cRunner.Start(ctx, true, false)
	if err != nil {
		t.Fatalf("Could not start golang container for wget/curl checks: %s", err)
	}

	dns := strings.ReplaceAll(dnsAddr, ":53", "")
	if len(dnsAddr) > 0 {
		cmd := []string{"sh", "-c", "echo 'search dadgarcorp.com' > /etc/resolv.conf && echo 'nameserver " + dns + "' >> /etc/resolv.conf"}
		stdout, stderr, retcode, err := cRunner.RunCmdWithOutput(ctx, result.Container.ID, cmd)
		if err != nil {
			t.Fatalf("Could not run command (%v) in container: %v", cmd, err)
		}

		if len(stderr) != 0 {
			t.Logf("Got stderr from command (%v):\n%v\n", cmd, string(stderr))
		}

		if retcode != 0 {
			t.Logf("Got stdout from command (%v):\n%v\n", cmd, string(stdout))
			t.Fatalf("Got unexpected non-zero retcode from command (%v): %v\n", cmd, retcode)
		}
	}

	cmd := []string{"curl", "--verbose", "--cacert", "/root.pem", "https://" + address + "/v1/sys/health"}
	stdout, stderr, retcode, err := cRunner.RunCmdWithOutput(ctx, result.Container.ID, cmd)
	if err != nil {
		t.Fatalf("Could not run command (%v) in container: %v", cmd, err)
	}

	if len(stderr) != 0 {
		t.Logf("Got stderr from command (%v):\n%v\n", cmd, string(stderr))
	}

	if (retcode != 0) != expectFail {
		t.Logf("Got stdout from command (%v):\n%v\n", cmd, string(stdout))
		t.Fatalf("Got unexpected retcode (expect fail: %v) from command (%v): %v\n", expectFail, cmd, retcode)
	}
}
