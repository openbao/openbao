package xfile

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/api/auth/approle/v2"
	"github.com/openbao/openbao/api/v2"
)

func cloneClient(ctx context.Context, client *api.Client, pname string) (*api.Client, error) {
	_, err := client.Logical().WriteWithContext(ctx, "sys/namespaces/"+pname, nil)
	if err != nil {
		return nil, err
	}
	clone, err := client.Clone()
	if err != nil {
		return nil, err
	}
	clone.SetToken(client.Token())
	clone.SetNamespace(pname)
	return clone, nil
}

func getApprole(client *api.Client, ctx context.Context, path, roleName string, policies ...string) (roleID, secretID, token string, err error) {
	if len(policies) == 0 {
		policies = []string{"default"}
	}

	sys := client.Sys()
	logical := client.Logical()

	err = sys.EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return
	}
	_, err = logical.WriteWithContext(ctx, "auth/"+path+"/role/"+roleName, map[string]interface{}{
		"policies": policies,
	})
	if err != nil {
		return
	}
	secret, err := logical.WriteWithContext(ctx, "auth/"+path+"/role/"+roleName+"/secret-id", nil)
	if err != nil {
		return
	}
	secretID = secret.Data["secret_id"].(string)
	secret, err = logical.ReadWithContext(ctx, "auth/"+path+"/role/"+roleName+"/role-id")
	if err != nil {
		return
	}
	roleID = secret.Data["role_id"].(string)

	auth, err := approle.NewAppRoleAuth(roleID, &approle.SecretID{FromString: secretID})
	if err != nil {
		return
	}
	secret, err = auth.Login(ctx, client)
	if err != nil {
		return
	}
	if secret.Auth == nil {
		err = fmt.Errorf("No auth data")
		return
	}

	token = secret.Auth.ClientToken

	return
}

func dropApprole(client *api.Client, ctx context.Context, secretID, path, roleName string) error {
	sys := client.Sys()
	logical := client.Logical()

	_, err := logical.WriteWithContext(ctx, "auth/"+path+"/role/"+roleName+"/secret-id/destroy", map[string]interface{}{
		"secret_id": secretID,
	})
	if err != nil {
		return err
	}

	_, err = logical.DeleteWithContext(ctx, "auth/"+path+"/role/"+roleName)
	if err != nil {
		return err
	}

	secret, err := logical.ListWithContext(ctx, "auth/"+path+"/role")
	if err != nil {
		return err
	}
	if secret != nil {
		return fmt.Errorf("List response: %+v", secret)
	}

	return sys.DisableAuthWithContext(ctx, path)
}

func getReadApproleRule() string {
	return `
	path "auth/approle/role/*" {
		capabilities = ["read"]
	}
	`
}

func getDefaultRule() string {
	// the "less" policy is the same as default but without the ability to renew tokens
	return `
		# Allow tokens to look up their own properties
		path "auth/token/lookup-self" {
		    capabilities = ["read"]
		}

		# Allow tokens to renew themselves
		path "auth/token/renew-self" {
		    capabilities = ["update"]
		}

		# Allow tokens to revoke themselves
		path "auth/token/revoke-self" {
		    capabilities = ["update"]
		}

		# Allow a token to look up its own capabilities on a path
		path "sys/capabilities-self" {
		    capabilities = ["update"]
		}

		# Allow a token to look up its own entity by id or name
		path "identity/entity/id/{{identity.entity.id}}" {
		  capabilities = ["read"]
		}
		path "identity/entity/name/{{identity.entity.name}}" {
		  capabilities = ["read"]
		}


		# Allow a token to look up its resultant ACL from all policies. This is useful
		# for UIs. It is an internal path because the format may change at any time
		# based on how the internal ACL features and capabilities change.
		path "sys/internal/ui/resultant-acl" {
		    capabilities = ["read"]
		}

		# Allow a token to renew a lease via lease_id in the request body; old path for
		# old clients, new path for newer
		path "sys/renew" {
		    capabilities = ["update"]
		}
		path "sys/leases/renew" {
		    capabilities = ["update"]
		}

		# Allow looking up lease properties. This requires knowing the lease ID ahead
		# of time and does not divulge any sensitive information.
		path "sys/leases/lookup" {
		    capabilities = ["update"]
		}

		# Allow a token to manage its own cubbyhole
		path "cubbyhole/*" {
		    capabilities = ["create", "read", "update", "delete", "list"]
		}

		# Allow a token to wrap arbitrary values in a response-wrapping token
		path "sys/wrapping/wrap" {
		    capabilities = ["update"]
		}

		# Allow a token to look up the creation time and TTL of a given
		# response-wrapping token
		path "sys/wrapping/lookup" {
		    capabilities = ["update"]
		}

		# Allow a token to unwrap a response-wrapping token. This is a convenience to
		# avoid client token swapping since this is also part of the response wrapping
		# policy.
		path "sys/wrapping/unwrap" {
		    capabilities = ["update"]
		}

		# Allow general purpose tools
		path "sys/tools/hash" {
		    capabilities = ["update"]
		}
		path "sys/tools/hash/*" {
		    capabilities = ["update"]
		}

		# Allow a token to make requests to the Authorization Endpoint for OIDC providers.
		path "identity/oidc/provider/+/authorize" {
		    capabilities = ["read", "update"]
		}
	`
}
