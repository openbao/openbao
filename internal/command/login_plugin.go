package command

import (
	"os"
	"os/exec"

	"github.com/openbao/openbao/api/v2"
)

type execLoginHandler struct {
	path string
}

// Auth(*api.Client, map[string]string, bool) (*api.Secret, error)
// Help() string
func (h *execLoginHandler) Auth(client *api.Client, config map[string]string, nonInteractive bool) (*api.Secret, error) {
	cmd := exec.Command(h.path + " help")
	cmd.Env = append(os.Environ(),
		"BAO_CLI_PLUGIN=1",
	)
	if nonInteractive {
		cmd.Env = append(cmd.Env, "BAO_CLI_AUTH_NON_INTERACTIVE=1")
	}
	if v, ok := config["mount"]; ok {
		cmd.Env = append(cmd.Env, "BAO_CLI_AUTH_MOUNT="+v)
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
}

func (h *execLoginHandler) Help() string {
	cmd := exec.Command(h.path + " help")
	cmd.Env = append(os.Environ(),
		"BAO_CLI_PLUGIN=1",
	)
	helpText, err := cmd.Output()
	if err != nil {
		return err.Error()
	}
	return string(helpText)
}
