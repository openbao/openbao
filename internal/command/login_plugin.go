package command

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/openbao/openbao/api/v2"
)

type execLoginHandler struct {
	path string
}

func (h *execLoginHandler) Auth(client *api.Client, config map[string]string, nonInteractive bool) (*api.Secret, error) {
	cleanEnv := make([]string, 0)
	for _, v := range os.Environ() {
		if strings.HasPrefix(v, api.EnvVaultToken) || strings.HasPrefix(v, "VAULT_TOKEN") {
			continue
		}
		cleanEnv = append(cleanEnv, v)
	}

	cmd := exec.Command(h.path, "login")
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = append(cleanEnv,
		"BAO_CLI_PLUGIN=1",
		"BAO_ADDR="+client.Address(),
		"BAO_NAMESPACE="+client.Namespace(),
	)
	if nonInteractive {
		cmd.Env = append(cmd.Env, "BAO_CLI_AUTH_NON_INTERACTIVE=1")
	}
	if v, ok := config["mount"]; ok {
		cmd.Env = append(cmd.Env, "BAO_CLI_AUTH_MOUNT="+v)
	}
	if v, ok := config["username"]; ok {
		cmd.Env = append(cmd.Env, "BAO_CLI_AUTH_USERNAME="+v)
	}
	if v, ok := config["password"]; ok {
		cmd.Env = append(cmd.Env, "BAO_CLI_AUTH_PASSWORD="+v)
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return api.ParseSecret(bytes.NewReader(output))
}

func (h *execLoginHandler) Help() string {
	cmd := exec.Command(h.path, "help")
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"BAO_CLI_PLUGIN=1",
	)
	helpText, err := cmd.Output()
	if err != nil {
		return err.Error()
	}
	return string(helpText)
}
