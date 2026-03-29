package joinplugin

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/testhelpers/corehelpers"
	"github.com/openbao/openbao/helper/testhelpers/pluginhelpers"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/stretchr/testify/require"
)

func TestJoinPlugin(t *testing.T) {
	pluginDir, cleanup := corehelpers.MakeTestPluginDir(t)
	t.Cleanup(func() { cleanup(t) })
	plugin := pluginhelpers.CompilePlugin(t, consts.PluginTypeJoin, "", pluginDir)

	serverConf := &server.Config{
		PluginDirectory: pluginDir,
		Plugins: []*server.PluginConfig{{
			Type:      consts.PluginTypeJoin.String(),
			Name:      "foo",
			Command:   plugin.FileName,
			Env:       []string{},
			Args:      []string{},
			SHA256Sum: plugin.Sha256,
		}},
	}

	conf := map[string]string{"addresses": "https://127.0.0.1:8200,https://127.0.0.2:8201"}

	catalog, err := NewCatalog(hclog.NewNullLogger(), serverConf)
	require.NoError(t, err, "should create join plugin catalog")

	join, builtin, err := catalog.NewJoin("foo")
	require.NoError(t, err, "should create foo plugin")
	require.False(t, builtin, "foo plugin should not be builtin")

	candidates, err := join.Candidates(context.TODO(), conf)
	require.NoError(t, err, "should get candidates")
	require.Equal(t, 2, len(candidates), "should return two candidates")

	join, builtin, err = catalog.NewJoin("static")
	require.NoError(t, err, "should create foo plugin")
	require.True(t, builtin, "foo plugin should not be builtin")

	candidates, err = join.Candidates(context.TODO(), conf)
	require.NoError(t, err, "should get candidates")
	require.Equal(t, 2, len(candidates), "should return two candidates")
}
