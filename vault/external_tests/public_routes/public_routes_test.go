package public_routes

import (
	"testing"

	"github.com/openbao/openbao/api/v2"
	vaulthttp "github.com/openbao/openbao/http"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault"
	"github.com/stretchr/testify/require"
)

func TestPublicRoutes_PathAccess(t *testing.T) {
	t.Parallel()
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"test-backend": vault.TestPublicRoutesBackendFactory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc:         vaulthttp.Handler,
		PublicRouteListener: true,
	})
	cluster.Start()
	defer cluster.Cleanup()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client

	err := client.Sys().Mount("test-backend", &api.MountInput{
		Type: "test-backend",
	})
	if err != nil {
		t.Fatalf("failed to mount test backend: %v", err)
	}

	// Ensure that the public and private routes are accessible via the tls-protected listener
	{
		_, err = client.Logical().Read("test-backend/unauthenticated/private")
		require.NoError(t, err, "Could not access path from main listener")

		_, err = client.Logical().Read("test-backend/unauthenticated/public")
		require.NoError(t, err, "Could not access path from main listener")
	}

	publicRouteClient := cluster.Cores[0].PublicRouteClient

	// Ensure the that public and private routes cannot be accessed via the public listener since
	// 'expose_public_paths' has not been enabled
	{
		_, err = publicRouteClient.Logical().Read("test-backend/unauthenticated/private")
		require.Error(t, err, "Access to the private route via the public route listener must be rejected")

		_, err = publicRouteClient.Logical().Read("test-backend/unauthenticated/public")
		require.Error(t, err, "Access to the public route via the public route listener must be rejected")
	}

	// Enable 'expose_public_paths'
	_, err = client.Logical().Write("/sys/mounts/test-backend/tune", map[string]interface{}{
		"expose_public_paths": true,
	})
	require.NoError(t, err, "Could not tune backend 'expose_public_paths'")

	{
		// Ensure that the private path is still unaccessible via the public listener
		_, err = publicRouteClient.Logical().Read("test-backend/unauthenticated/private")
		require.Error(t, err, "Access to the private route via the public route listener must be rejected")

		// Ensure that the public route listener is now accessible via the public listener
		_, err = publicRouteClient.Logical().Read("test-backend/unauthenticated/public")
		require.NoError(t, err, "Could not access public path via public route listener")
	}

	// Disable 'expose_public_paths'
	_, err = client.Logical().Write("/sys/mounts/test-backend/tune", map[string]interface{}{
		"expose_public_paths": false,
	})
	require.NoError(t, err, "Could not tune backend 'expose_public_paths'")

	// Ensure that both paths are no longer accessible via the public listener
	{
		_, err = publicRouteClient.Logical().Read("test-backend/unauthenticated/private")
		require.Error(t, err, "Access to the private route via the public route listener must be rejected")

		_, err = publicRouteClient.Logical().Read("test-backend/unauthenticated/public")
		require.Error(t, err, "Access to the public route via the public route listener must be rejected")
	}
}

func TestPublicRoutes_Configure(t *testing.T) {
	t.Parallel()
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"test-backend": vault.TestPublicRoutesBackendFactory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
	})
	cluster.Start()
	defer cluster.Cleanup()

	vault.TestWaitActive(t, cluster.Cores[0].Core)
	client := cluster.Cores[0].Client

	err := client.Sys().Mount("test-backend", &api.MountInput{
		Type: "test-backend",
	})
	if err != nil {
		t.Fatalf("failed to mount test backend: %v", err)
	}

	// Read default tuneConfig
	{
		tuneConfig, err := client.Logical().Read("/sys/mounts/test-backend/tune")

		require.NoError(t, err, "Could not read tune config")

		require.NotNil(t, tuneConfig, "Could not read tune config")
		require.NotNil(t, tuneConfig.Data, "Could not read tune config")
		require.NotNil(t, tuneConfig.Data["expose_public_paths"], "'expose_public_paths' is nil")

		exposePublicPathsVal, ok := tuneConfig.Data["expose_public_paths"].(bool)
		if !ok {
			t.Error("'expose_public_paths' value is not a boolean")
		}
		require.False(t, exposePublicPathsVal, "'expose_public_paths' must be set to false")
	}

	// Enable 'expose_public_paths'
	{
		_, err = client.Logical().Write("/sys/mounts/test-backend/tune", map[string]interface{}{
			"expose_public_paths": true,
		})
		require.NoError(t, err, "Could not tune backend 'expose_public_paths'")

		tuneConfig, err := client.Logical().Read("/sys/mounts/test-backend/tune")

		require.NoError(t, err, "Could not read tune config")

		require.NotNil(t, tuneConfig, "Could not read tune config")
		require.NotNil(t, tuneConfig.Data, "Could not read tune config")
		require.NotNil(t, tuneConfig.Data["expose_public_paths"], "'expose_public_paths' is nil")

		exposePublicPathsVal, ok := tuneConfig.Data["expose_public_paths"].(bool)
		if !ok {
			t.Error("'expose_public_paths' value is not a boolean")
		}
		require.True(t, exposePublicPathsVal, "'expose_public_paths' must be set to true")
	}

	// Disable 'expose_public_paths'
	{
		_, err = client.Logical().Write("/sys/mounts/test-backend/tune", map[string]interface{}{
			"expose_public_paths": false,
		})
		require.NoError(t, err, "Could not tune backend 'expose_public_paths'")

		tuneConfig, err := client.Logical().Read("/sys/mounts/test-backend/tune")

		require.NoError(t, err, "Could not read tune config")

		require.NotNil(t, tuneConfig, "Could not read tune config")
		require.NotNil(t, tuneConfig.Data, "Could not read tune config")
		require.NotNil(t, tuneConfig.Data["expose_public_paths"], "'expose_public_paths' is nil")

		exposePublicPathsVal, ok := tuneConfig.Data["expose_public_paths"].(bool)
		if !ok {
			t.Error("'expose_public_paths' value is not a boolean")
		}
		require.False(t, exposePublicPathsVal, "'expose_public_paths' must be set to false")
	}
}
