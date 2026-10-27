package userpass

import (
	"regexp"
	"strings"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
)

var validUsername = regexp.MustCompile("^" + framework.GenericNameRegex("username") + "$")

// During routing, anything except "/" is acceptable in a username. 
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