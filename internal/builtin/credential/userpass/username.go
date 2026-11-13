package userpass

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
)

// Define username rules. Usernames are allowed to contain alphanumeric characters, -, ., and @
var validUsername = regexp.MustCompile("^" + framework.GenericNameWithAtRegex("username") + "$")

// During routing, anything except "/" is acceptable in a username. Routing only checks for endpoint matches. Username rules are checked separately.
func usernamePathRegex() string {
	return `(?P<username>[^/]+)`
}

// Read username and reinforce actual rules
func getUsername(d *framework.FieldData) (string, error) {
	username := strings.ToLower(d.Get("username").(string))
	// Reject empty username
	if username == "" {
		return "", errors.New("missing username")
	}
	// Check against username rules
	if !validUsername.MatchString(username) {
		return "", fmt.Errorf("invalid username: %q", username)
	}
	return username, nil
}
