// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package userpass_binary

import (
	"context"
	_ "embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/openbao/openbao/api/auth/userpass/v2"
	"github.com/openbao/openbao/api/v2"
	hDocker "github.com/openbao/openbao/sdk/v2/helper/docker"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster"
	"github.com/openbao/openbao/sdk/v2/helper/testcluster/docker"

	"github.com/stretchr/testify/require"
)

var adminPolicy = `
path "*" {
    capabilities  = ["create", "update", "delete", "read", "patch", "list", "sudo"]
}
`

func Test_StrictIPBinding(t *testing.T) {
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
		ClusterOptions: testcluster.ClusterOptions{
			VaultNodeConfig: &testcluster.VaultNodeConfig{
				LogLevel: "TRACE",
			},
			NumCores: 1,
		},
	}

	cluster := docker.NewTestDockerCluster(t, opts)
	defer cluster.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	nodeIndex, err := testcluster.WaitForActiveNode(ctx, cluster)
	require.NoError(t, err)

	node := cluster.ClusterNodes[nodeIndex]
	client := node.APIClient()

	vaultNetwork := cluster.ClusterNodes[0].ContainerNetworkName
	vaultAddr := node.ContainerIPAddress

	err = client.Sys().PutPolicy("admin", adminPolicy)
	require.NoError(t, err)

	err = client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	require.NoError(t, err)

	_, err = client.Logical().Write("auth/userpass/users/testing", map[string]interface{}{
		"password":               "password",
		"token_policies":         "admin",
		"token_strictly_bind_ip": true,
	})
	require.NoError(t, err)

	// Login to userpass and attempt to use it via cURL.
	up, err := userpass.NewUserpassAuth("testing",
		&userpass.Password{
			FromString: "password",
		},
		userpass.WithMountPath("userpass"),
	)
	require.NoError(t, err)
	require.NotNil(t, up)

	resp, err := client.Auth().Login(ctx, up)
	require.NoError(t, err)
	require.NotNil(t, resp)

	localToken := resp.Auth.ClientToken

	sleepTimer := "45"
	curlRunner, err := hDocker.NewServiceRunner(hDocker.RunOptions{
		ImageRepo:     "docker.mirror.hashicorp.services/curlimages/curl",
		ImageTag:      "8.4.0",
		ContainerName: "curl_test_ip_binding",
		NetworkName:   vaultNetwork,
		Entrypoint:    []string{"sleep", sleepTimer},
		LogConsumer: func(s string) {
			t.Log(s)
		},
	})
	require.NoError(t, err, "failed creating cURL service runner")

	curlResult, err := curlRunner.Start(ctx, true, false)
	require.NoError(t, err, "could not start cURL container")
	require.NotNil(t, curlResult, "could not start cURL container")

	curlCmd := []string{
		"curl",
		"-sSL",
		"--insecure",
		"--header", "X-Vault-Token: " + localToken,
		"https://" + vaultAddr + ":8200/v1/sys/host-info",
	}
	stdout, stderr, retcode, err := curlRunner.RunCmdWithOutput(ctx, curlResult.Container.ID, curlCmd)
	t.Logf("cURL Command: %v\nstdout: %v\nstderr: %v\n", curlCmd, string(stdout), string(stderr))
	require.NoError(t, err, "got error running cURL command")
	require.Contains(t, string(stdout), "permission denied", "expected failure retcode cURL command result")
	require.Zero(t, retcode)

	cloned, err := client.Clone()
	require.NoError(t, err)

	// ...but using the token locally should work.
	cloned.SetToken(localToken)
	resp, err = cloned.Logical().Read("sys/host-info")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Authenticating via curl should work.
	curlCmd = []string{
		"curl",
		"-sSL",
		"--insecure",

		"-H", "Content-Type: application/json",
		"--data", `{"password": "password"}`,
		// We switch the username to Testing to ensure case validation
		// does not affect user lockout attribution. This is a test
		// to validate our fix for HCSEC-2025-16 / CVE-2025-6004.
		"https://" + vaultAddr + ":8200/v1/auth/userpass/login/Testing",
	}
	stdout, stderr, retcode, err = curlRunner.RunCmdWithOutput(ctx, curlResult.Container.ID, curlCmd)
	t.Logf("cURL Command: %v\nstdout: %v\nstderr: %v\n", curlCmd, string(stdout), string(stderr))
	require.NoError(t, err, "got error running cURL command")
	require.Equal(t, 0, retcode, "unexpected failure retcode cURL command result")

	var data map[string]interface{}
	err = json.Unmarshal(stdout, &data)
	require.NoError(t, err)
	require.NotContains(t, data, "errors")
	require.Contains(t, data, "auth")

	auth := data["auth"].(map[string]interface{})
	require.Contains(t, auth, "client_token")
	remoteToken := auth["client_token"].(string)

	// Using the remote token locally should fail...
	cloned.SetToken(remoteToken)
	resp, err = cloned.Logical().Read("sys/host-info")
	require.Error(t, err)

	// ...but using it remotely should work fine
	curlCmd = []string{
		"curl",
		"-sSL",
		"--insecure",
		"--header", "X-Vault-Token: " + remoteToken,
		"https://" + vaultAddr + ":8200/v1/sys/host-info",
	}
	stdout, stderr, retcode, err = curlRunner.RunCmdWithOutput(ctx, curlResult.Container.ID, curlCmd)
	t.Logf("cURL Command: %v\nstdout: %v\nstderr: %v\n", curlCmd, string(stdout), string(stderr))
	require.NoError(t, err, "got error running cURL command")
	require.Equal(t, 0, retcode, "unexpected failure retcode cURL command result")
	require.Contains(t, string(stdout), "vendorId")
}
