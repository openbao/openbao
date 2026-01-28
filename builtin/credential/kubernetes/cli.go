package kubeauth

import (
	"errors"
	"fmt"
	"os"
	"strings"

	pwd "github.com/hashicorp/go-secure-stdlib/password"
	"github.com/openbao/openbao/api/v2"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string, nonInteractive bool) (*api.Secret, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "kubernetes"
	}

	role, ok := m["role"]
	if !ok {
		return nil, errors.New("'role' must be supplied")
	}

	jwt, ok := m["jwt"]
	if !ok {
		if jwt == "" {
			if nonInteractive {
				return nil, errors.New("'jwt' not supplied and refusing to pull from stdin")
			}

			fmt.Fprintf(os.Stderr, "JWT (will be hidden): ")
			var err error
			jwt, err = pwd.Read(os.Stdin)
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil {
				return nil, err
			}
		}
	}

	data := map[string]interface{}{
		"jwt":  jwt,
		"role": role,
	}

	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := c.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("empty response from credential provider")
	}

	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: bao login -method=kubernetes [CONFIG K=V...]

  The Kubernetes auth method allows users to authenticate using a Kubernetes service account token.

  Authenticate using role "dev-role", prompting for JWT on stdin:

      $ bao login -method=kubernetes role=dev-role
      JWT (will be hidden):

  Authenticate using role "dev-role", providing JWT directly:

      $ bao login -method=kubernetes role=dev-role jwt="<token>"

Configuration:

  jwt=<string>
      Kubernetes service account token to use for authentication. If this is not set, the
			CLI will prompt for this on stdin.

  role=<string>
      Kubernetes role to use for authentication.
`

	return strings.TrimSpace(help)
}
