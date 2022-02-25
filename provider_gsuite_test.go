package jwtauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

const (
	googleCredentialsEnv = "GOOGLE_CREDENTIALS"
	gsuiteAdminEmailEnv  = "GSUITE_ADMIN_EMAIL"
)

// getTestCreds gets credentials needed to run tests from environment variables.
// It will log and skip the test if the required credentials are not set.
func getTestCreds(t *testing.T) (string, string) {
	c := os.Getenv(googleCredentialsEnv)
	if c == "" {
		t.Logf("skip: must set env var %q to a valid service account key file path", googleCredentialsEnv)
		t.SkipNow()
	}

	a := os.Getenv(gsuiteAdminEmailEnv)
	if a == "" {
		t.Logf("skip: must set env var %q to a gsuite admin email address", gsuiteAdminEmailEnv)
		t.SkipNow()
	}

	return c, a
}

// Tests fetching groups from G Suite using the provider configuration.
//
// To run the tests:
//   1. Supply credentials via environment variables as detailed in getTestCreds()
//   2. Supply the G Suite userName and expected groups to be fetched for the user in the test table
func TestGSuiteProvider_FetchGroups(t *testing.T) {
	creds, adminEmail := getTestCreds(t)

	type args struct {
		userName string
		config   *jwtConfig
	}
	tests := []struct {
		name     string
		args     args
		expected []interface{}
	}{
		{
			name: "fetch groups from gsuite with default recursion max depth 0",
			args: args{
				userName: "fill_in_user_before_running",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"provider":                 "gsuite",
						"gsuite_service_account":   creds,
						"gsuite_admin_impersonate": adminEmail,
						"fetch_groups":             true,
					},
				},
			},
			expected: []interface{}{
				// Fill in expected groups before running
				// Example: "group1", "group2",
			},
		},
		{
			name: "fetch groups from gsuite with recursion max depth 1",
			args: args{
				userName: "fill_in_user_before_running",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"provider":                 "gsuite",
						"gsuite_service_account":   creds,
						"gsuite_admin_impersonate": adminEmail,
						"fetch_groups":             true,
						"groups_recurse_max_depth": 1,
					},
				},
			},
			expected: []interface{}{
				// Fill in expected groups before running
				// Example: "group1", "group2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := getBackend(t)
			ctx := context.Background()

			// Configure the provider
			gProvider := new(GSuiteProvider)
			err := gProvider.Initialize(ctx, tt.args.config)
			assert.NoError(t, err)

			// Fetch groups from G Suite
			allClaims := map[string]interface{}{
				"sub": tt.args.userName,
			}
			role := &jwtRole{
				UserClaim:   "sub",
				GroupsClaim: "groups",
			}
			groupsRaw, err := gProvider.FetchGroups(ctx, b.(*jwtAuthBackend), allClaims, role, nil)
			assert.NoError(t, err)

			// Assert that groups are as expected
			groupsResp, ok := normalizeList(groupsRaw)
			assert.True(t, ok)
			assert.ElementsMatch(t, tt.expected, groupsResp)
		})
	}
}

// Tests fetching user custom schemas from G Suite using the provider configuration.
//
// To run the tests:
//   1. Supply credentials via environment variables as detailed in getTestCreds()
//   2. Supply the G Suite userName, user_custom_schemas, and expected custom schema
//      values to be fetched as claims in the test table
func TestGSuiteProvider_FetchUserInfo(t *testing.T) {
	creds, adminEmail := getTestCreds(t)

	type args struct {
		userName string
		config   *jwtConfig
	}
	tests := []struct {
		name     string
		args     args
		expected map[string]interface{}
	}{
		{
			name: "fetch user info from custom schemas in gsuite",
			args: args{
				userName: "fill_in_user_before_running",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"provider":                 "gsuite",
						"gsuite_service_account":   creds,
						"gsuite_admin_impersonate": adminEmail,
						"fetch_user_info":          true,
						"user_custom_schemas":      "fill_in_custom_schemas_before_running",
					},
				},
			},
			expected: map[string]interface{}{
				// Fill in expected custom schema claims before running
				// Example:
				// "Preferences": map[string]interface{}{
				// 	"shirt_size": "medium",
				// },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := getBackend(t)
			ctx := context.Background()

			// Configure the provider
			gProvider := new(GSuiteProvider)
			err := gProvider.Initialize(ctx, tt.args.config)
			assert.NoError(t, err)

			// Fetch user info from G Suite
			allClaims := map[string]interface{}{
				"sub": tt.args.userName,
			}
			role := &jwtRole{
				UserClaim:   "sub",
				GroupsClaim: "groups",
			}
			err = gProvider.FetchUserInfo(ctx, b.(*jwtAuthBackend), allClaims, role)
			assert.NoError(t, err)

			// Assert that expected user info is added to the JWT claims
			customSchemas := tt.args.config.ProviderConfig["user_custom_schemas"].(string)
			for _, schema := range strings.Split(customSchemas, ",") {
				assert.Equal(t, tt.expected[schema], allClaims[schema])
			}
		})
	}
}

// Tests the user and group recursion logic in the search method.
func TestGSuiteProvider_search(t *testing.T) {
	groupsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, _ := url.ParseQuery(r.URL.RawQuery)
		switch m["userKey"][0] {
		case "user1":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group1@group.com"
				}]
			}`))
		case "group1@group.com":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group2@group.com"
				}]
			}`))
		case "group2@group.com":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group3@group.com"
				}]
			}`))
		case "group3@group.com":
			w.Write([]byte(`{"kind": "admin#directory#groups", "groups": []}`))
		case "noGroupUser":
			w.Write([]byte(`{"kind": "admin#directory#groups", "groups": []}`))
		}
	}))
	defer groupsServer.Close()

	type args struct {
		user   string
		config *jwtConfig
	}
	tests := []struct {
		name     string
		args     args
		expected []string
	}{
		{
			name: "fetch groups for user that's in no groups",
			args: args{
				user: "noGroupUser",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
					},
				},
			},
			expected: []string{},
		},
		{
			name: "fetch groups for group that's in no groups",
			args: args{
				user: "group3@group.com",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
					},
				},
			},
			expected: []string{},
		},
		{
			name: "fetch groups for user with default recursion max depth 0",
			args: args{
				user: "user1",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
					},
				},
			},
			expected: []string{
				"group1@group.com",
			},
		},
		{
			name: "fetch groups for user with recursion max depth 1",
			args: args{
				user: "user1",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
						"groups_recurse_max_depth": 1,
					},
				},
			},
			expected: []string{
				"group1@group.com",
				"group2@group.com",
			},
		},
		{
			name: "fetch groups for user with recursion max depth 10",
			args: args{
				user: "user1",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
						"groups_recurse_max_depth": 10,
					},
				},
			},
			expected: []string{
				"group1@group.com",
				"group2@group.com",
				"group3@group.com",
			},
		},
		{
			name: "fetch groups for group with default recursion max depth 0",
			args: args{
				user: "group1@group.com",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
					},
				},
			},
			expected: []string{
				"group2@group.com",
			},
		},
		{
			name: "fetch groups for group with recursion max depth 1",
			args: args{
				user: "group1@group.com",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
						"groups_recurse_max_depth": 1,
					},
				},
			},
			expected: []string{
				"group2@group.com",
				"group3@group.com",
			},
		},
		{
			name: "fetch groups for group with recursion max depth 10",
			args: args{
				user: "group1@group.com",
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"fetch_groups":             true,
						"groups_recurse_max_depth": 10,
					},
				},
			},
			expected: []string{
				"group2@group.com",
				"group3@group.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Initialize the provider
			gProvider := new(GSuiteProvider)
			assert.NoError(t, gProvider.Initialize(ctx, tt.args.config))

			// Fetch groups from the groupsServer
			gProvider.adminSvc, _ = admin.NewService(ctx, option.WithHTTPClient(&http.Client{}))
			gProvider.adminSvc.BasePath = groupsServer.URL
			groups := make(map[string]bool)
			assert.NoError(t, gProvider.search(ctx, groups, tt.args.user, gProvider.config.GroupsRecurseMaxDepth))

			// Assert that groups are as expected
			assert.Equal(t, len(tt.expected), len(groups))
			for _, group := range tt.expected {
				_, ok := groups[group]
				assert.True(t, ok)
			}
		})
	}
}

func TestGSuiteProvider_Initialize(t *testing.T) {
	type args struct {
		config *jwtConfig
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid config: required service account key is empty",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_admin_impersonate": "test@example.com",
						"groups_recurse_max_depth": -1,
						"user_custom_schemas":      "Custom",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid config: required admin impersonate email is empty",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"groups_recurse_max_depth": -1,
						"user_custom_schemas":      "Custom",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid config: recurse max depth negative number",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"groups_recurse_max_depth": -1,
						"user_custom_schemas":      "Custom",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid config: all options",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"groups_recurse_max_depth": 5,
						"user_custom_schemas":      "Custom",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config: no custom schemas",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"groups_recurse_max_depth": 5,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config: no recurse max depth",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"user_custom_schemas":      "Custom",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config: fetch groups and user info",
			args: args{
				config: &jwtConfig{
					ProviderConfig: map[string]interface{}{
						"gsuite_service_account":   `{"type": "service_account"}`,
						"gsuite_admin_impersonate": "test@example.com",
						"user_custom_schemas":      "Custom",
						"fetch_groups":             true,
						"fetch_user_info":          true,
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &GSuiteProvider{}
			err := g.Initialize(context.Background(), tt.args.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// Tests that bound claims set on a role can be validated after
// provider-specific group and user info fetching has occurred.
func TestGSuiteProvider_validateBoundClaims(t *testing.T) {
	b, _ := getBackend(t)
	ctx := context.Background()

	// Mock the G Suite groups and users APIs
	gServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/groups":
			w.Write([]byte(`{
				"kind": "admin#directory#groups",
				"groups": [{
					"kind": "admin#directory#group",
					"email": "group1@example.com"
				}]
			}`))
		case "/users/user1@example.com":
			w.Write([]byte(`{
				"kind": "admin#directory#user",
				"customSchemas": {
					"Preferences": {
						"shirt_size": "medium"
					}
				}
			}`))
		}
	}))
	defer gServer.Close()

	// Set up claims
	allClaims := map[string]interface{}{
		"email": "user1@example.com",
	}

	// The bound claims set of the role will be validated
	// after provider-specific groups and user info fetching
	jwtRole := &jwtRole{
		AllowedRedirectURIs: []string{"http://example.com"},
		UserClaim:           "email",
		GroupsClaim:         "groups",
		BoundClaims: map[string]interface{}{
			"groups":                  "group1@example.com",
			"/Preferences/shirt_size": "medium",
		},
	}

	// Configure the provider
	config := &jwtConfig{
		ProviderConfig: map[string]interface{}{
			"gsuite_service_account":   `{"type": "service_account"}`,
			"gsuite_admin_impersonate": "admin@example.com",
			"fetch_groups":             true,
			"fetch_user_info":          true,
			"groups_recurse_max_depth": 5,
			"user_custom_schemas":      "Preferences",
		},
	}
	provider := &GSuiteProvider{}
	err := provider.Initialize(ctx, config)
	assert.NoError(t, err)

	// Swap the base URL to make requests to gServer
	provider.adminSvc, _ = admin.NewService(ctx, option.WithHTTPClient(&http.Client{}))
	provider.adminSvc.BasePath = gServer.URL

	// Fetch the groups
	_, err = b.(*jwtAuthBackend).fetchGroups(ctx, provider, allClaims, jwtRole, nil)
	assert.NoError(t, err)

	// Fetch the user info
	err = b.(*jwtAuthBackend).fetchUserInfo(ctx, provider, allClaims, jwtRole)
	assert.NoError(t, err)

	// Ensure that bound_claims defined on the role are properly validated
	err = validateBoundClaims(b.Logger(), jwtRole.BoundClaimsType, jwtRole.BoundClaims, allClaims)
	assert.NoError(t, err)
}
