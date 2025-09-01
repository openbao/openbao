// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/cap/util"
	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/openbao/openbao/api/v2"
)

const (
	defaultMount          = "oidc"
	defaultListenAddress  = "localhost"
	defaultPort           = "8250"
	defaultCallbackHost   = "localhost"
	defaultCallbackMethod = "http"
	defaultCallbackMode   = "client"

	FieldCallbackHost   = "callbackhost"
	FieldCallbackMethod = "callbackmethod"
	FieldCallbackMode   = "callbackmode"
	FieldListenAddress  = "listenaddress"
	FieldPort           = "port"
	FieldCallbackPort   = "callbackport"
	FieldSkipBrowser    = "skip_browser"
	FieldQRCode         = "show_qr"
	FieldAbortOnError   = "abort_on_error"
)

var errorRegex = regexp.MustCompile(`(?s)Errors:.*\* *(.*)`)

type CLIHandler struct{}

// loginResp implements vault's command.LoginHandler interface, but we do not check
// the implementation as that'd cause an import loop.
type loginResp struct {
	secret *api.Secret
	err    error
}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string, nonInteractive bool) (*api.Secret, error) {
	// handle ctrl-c while waiting for the callback
	sigintCh := make(chan os.Signal, 1)
	signal.Notify(sigintCh, authHalts...)
	defer signal.Stop(sigintCh)

	mount, ok := m["mount"]
	if !ok {
		mount = defaultMount
	}

	listenAddress, ok := m[FieldListenAddress]
	if !ok {
		listenAddress = defaultListenAddress
	}

	port, ok := m[FieldPort]
	if !ok {
		port = defaultPort
	}

	var serverURL *url.URL
	callbackMode, ok := m[FieldCallbackMode]
	if !ok || callbackMode == "" {
		callbackMode = defaultCallbackMode
	} else if callbackMode == "direct" {
		serverAddr := api.ReadBaoVariable("BAO_ADDR")
		if serverAddr != "" {
			serverURL, _ = url.Parse(serverAddr)
		}
	}

	callbackHost, ok := m[FieldCallbackHost]
	if !ok {
		if serverURL != nil {
			callbackHost = serverURL.Hostname()
		} else {
			// Note that since defaultCallbackHost is localhost,
			// this only works if the cli is run on the server
			callbackHost = defaultCallbackHost
		}
	}

	callbackMethod, ok := m[FieldCallbackMethod]
	if !ok {
		if serverURL != nil {
			callbackMethod = serverURL.Scheme
		} else {
			callbackMethod = defaultCallbackMethod
		}
	}

	callbackPort, ok := m[FieldCallbackPort]
	if !ok {
		if serverURL != nil {
			callbackPort = serverURL.Port() + "/v1/auth/" + mount
		} else {
			callbackPort = port
		}
	}

	parseBool := func(f string, d bool) (bool, error) {
		s, ok := m[f]
		if !ok {
			return d, nil
		}

		v, err := strconv.ParseBool(s)
		if err != nil {
			return false, fmt.Errorf(
				"failed to parse value for %q, err=%w", f, err)
		}

		return v, nil
	}

	var skipBrowserLaunch bool
	if v, err := parseBool(FieldSkipBrowser, false); err != nil {
		return nil, err
	} else {
		skipBrowserLaunch = v
	}

	var showQR bool
	if v, err := parseBool(FieldQRCode, false); err != nil {
		return nil, err
	} else {
		showQR = v
	}

	var abortOnError bool
	if v, err := parseBool(FieldAbortOnError, false); err != nil {
		return nil, err
	} else {
		abortOnError = v
	}

	role := m["role"]

	authURL, clientNonce, secret, err := fetchAuthURL(c, role, mount, callbackPort, callbackMethod, callbackHost)
	if err != nil {
		return nil, err
	}

	doneCh := make(chan loginResp)

	var pollInterval string
	var interval int
	var state string
	var userCode string
	var listener net.Listener

	if secret != nil {
		pollInterval, _ = secret.Data["poll_interval"].(string)
		state, _ = secret.Data["state"].(string)
		userCode, _ = secret.Data["user_code"].(string)
	}
	if callbackMode != "client" {
		if state == "" {
			return nil, errors.New("no state returned in " + callbackMode + " callback mode")
		}
		if pollInterval == "" {
			return nil, errors.New("no poll_interval returned in " + callbackMode + " callback mode")
		}
		interval, err = strconv.Atoi(pollInterval)
		if err != nil {
			return nil, errors.New("cannot convert poll_interval " + pollInterval + " to integer")
		}
	} else {
		if state != "" {
			return nil, errors.New("state returned in client callback mode, try direct")
		}
		if pollInterval != "" {
			return nil, errors.New("poll_interval returned in client callback mode")
		}
		// Set up callback handler
		http.HandleFunc("/oidc/callback", callbackHandler(c, mount, clientNonce, doneCh))

		listener, err = net.Listen("tcp", listenAddress+":"+port)
		if err != nil {
			return nil, err
		}
		defer listener.Close()
	}

	// Open the default browser to the callback URL.
	if !skipBrowserLaunch {
		fmt.Fprintf(os.Stderr, "Complete the login via your OIDC provider. Launching browser to:\n\n    %s\n\n\n", authURL)
		if err := util.OpenURL(authURL); err != nil {
			if abortOnError {
				return nil, fmt.Errorf("failed to launch the browser %s=%t, err=%w", FieldAbortOnError, abortOnError, err)
			}
			fmt.Fprintf(os.Stderr, "Error attempting to automatically open browser: '%s'.\nPlease visit the authorization URL manually.", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Complete the login via your OIDC provider. Open the following link in your browser:\n\n    %s\n\n\n", authURL)
	}
	if showQR {
		printQR(os.Stderr, authURL)
	}
	fmt.Fprintf(os.Stderr, "Waiting for OIDC authentication to complete...\n")

	if userCode != "" {
		fmt.Fprintf(os.Stderr, "When prompted, enter code %s\n\n", userCode)
	}

	if callbackMode != "client" {
		data := map[string]interface{}{
			"state":        state,
			"client_nonce": clientNonce,
		}
		pollUrl := fmt.Sprintf("auth/%s/oidc/poll", mount)
		for {
			time.Sleep(time.Duration(interval) * time.Second)

			secret, err := c.Logical().Write(pollUrl, data)
			if err == nil {
				return secret, nil
			}
			if strings.HasSuffix(err.Error(), "slow_down") {
				interval *= 2
			} else if !strings.HasSuffix(err.Error(), "authorization_pending") {
				return nil, err
			}
			// authorization is pending, try again
		}
	}

	// Start local server
	go func() {
		err := http.Serve(listener, nil)
		if err != nil && err != http.ErrServerClosed {
			doneCh <- loginResp{nil, err}
		}
	}()

	// Wait for either the callback to finish, or a halt signal (e.g., SIGKILL, SIGINT, SIGTSTP) to be received or up to 2 minutes
	select {
	case s := <-doneCh:
		return s.secret, s.err
	case <-sigintCh:
		return nil, errors.New("Interrupted")
	case <-time.After(2 * time.Minute):
		return nil, errors.New("Timed out waiting for response from provider")
	}
}

func callbackHandler(c *api.Client, mount string, clientNonce string, doneCh chan<- loginResp) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var response string
		var secret *api.Secret
		var err error

		defer func() {
			w.Write([]byte(response))
			doneCh <- loginResp{secret, err}
		}()

		// Pull any parameters from either the body or query parameters.
		// FormValue prioritizes body values, if found.
		data := map[string][]string{
			"state":        {req.FormValue("state")},
			"code":         {req.FormValue("code")},
			"id_token":     {req.FormValue("id_token")},
			"client_nonce": {clientNonce},
		}

		// If this is a POST, then the form_post response_mode is being used and the flow
		// involves an extra step. First POST the data to Vault, and then issue a GET with
		// the same state/code to complete the auth as normal.
		if req.Method == http.MethodPost {
			url := c.Address() + path.Join("/v1/auth", mount, "oidc/callback")
			resp, err := http.PostForm(url, data)
			if err != nil {
				summary, detail := parseError(err)
				response = errorHTML(summary, detail)
				return
			}
			defer resp.Body.Close()

			// An id_token will never be part of a redirect GET, so remove it here too.
			delete(data, "id_token")
		}

		secret, err = c.Logical().ReadWithData(fmt.Sprintf("auth/%s/oidc/callback", mount), data)
		if err != nil {
			summary, detail := parseError(err)
			response = errorHTML(summary, detail)
		} else {
			response = successHTML
		}
	}
}

func fetchAuthURL(c *api.Client, role, mount, callbackPort string, callbackMethod string, callbackHost string) (string, string, *api.Secret, error) {
	var authURL string

	clientNonce, err := base62.Random(20)
	if err != nil {
		return "", "", nil, err
	}

	redirectURI := fmt.Sprintf("%s://%s:%s/oidc/callback", callbackMethod, callbackHost, callbackPort)
	data := map[string]interface{}{
		"role":         role,
		"redirect_uri": redirectURI,
		"client_nonce": clientNonce,
	}

	secret, err := c.Logical().Write(fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		return "", "", nil, err
	}

	if secret != nil {
		authURL = secret.Data["auth_url"].(string)
	}

	if authURL == "" {
		return "", "", nil, fmt.Errorf("Unable to authorize role %q with redirect_uri %q. Check OpenBao logs for more information.", role, redirectURI)
	}

	return authURL, clientNonce, secret, nil
}

// parseError converts error from the API into summary and detailed portions.
// This is used to present a nicer UI by splitting up *known* prefix sentences
// from the rest of the text. e.g.
//
//	"No response from provider. Gateway timeout from upstream proxy."
//
// becomes:
//
//	"No response from provider.", "Gateway timeout from upstream proxy."
func parseError(err error) (string, string) {
	headers := []string{errNoResponse, errLoginFailed, errTokenVerification}
	summary := "Login error"
	detail := ""

	errorParts := errorRegex.FindStringSubmatch(err.Error())
	switch len(errorParts) {
	case 0:
		summary = ""
	case 1:
		detail = errorParts[0]
	case 2:
		for _, h := range headers {
			if strings.HasPrefix(errorParts[1], h) {
				summary = h
				detail = strings.TrimSpace(errorParts[1][len(h):])
				break
			}
		}
		if detail == "" {
			detail = errorParts[1]
		}
	}

	return summary, detail
}

// Help method for OIDC cli
func (h *CLIHandler) Help() string {
	help := fmt.Sprintf(`
Usage: bao login -method=oidc [CONFIG K=V...]

  The OIDC auth method allows users to authenticate using an OIDC provider.
  The provider must be configured as part of a role by the operator.

  Authenticate using role "engineering":

      $ bao login -method=oidc role=engineering
      Complete the login via your OIDC provider. Launching browser to:

          https://accounts.google.com/o/oauth2/v2/...

  The default browser will be opened for the user to complete the login. 
  Alternatively, the user may visit the provided URL directly.

Configuration:

  role=<string>
    OpenBao role of type "OIDC" to use for authentication.

  %s=<string>
    Mode of callback: "client" for connection to the command line client,
    "direct" for direct connection to the server, or "device" for device
    flow which has no callback (default: client).

  %s=<string>
    Optional address to bind the OIDC callback listener to in client callback
    mode (default: localhost).

  %s=<string>
    Optional localhost port to use for OIDC callback in client callback mode
    (default: 8250).

  %s=<string>
    Optional method to use in OIDC redirect_uri (default: the method from
    $BAO_ADDR or $VAULT_ADDR in direct callback mode, else http)

  %s=<string>
    Optional callback host address to use in OIDC redirect_uri (default:
    the host from $BAO_ADDR or $VAULT_ADDR in direct callback mode, else
    localhost).

  %s=<string>
    Optional port to use in OIDC redirect_uri (default: the value set for
    port in client callback mode, else the port from $BAO_ADDR or $VAULT_ADDR
    with an added /v1/auth/<path> where <path> is from the login -path option).

  %s=<bool>
    Toggle the automatic launching of the default browser to the login URL. (default: false).

  %s=<bool>
    Display a QR code of the login URL. Requires UTF-8 support from your
    terminal emulator (default: false).

  %s=<bool>
    Abort on any error. (default: false).
`,
		FieldCallbackMode,
		FieldListenAddress, FieldPort, FieldCallbackMethod,
		FieldCallbackHost, FieldCallbackPort, FieldSkipBrowser,
		FieldQRCode, FieldAbortOnError,
	)

	return strings.TrimSpace(help)
}
