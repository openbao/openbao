package transit

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/builtin/logical/transit/kmip"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type kmipRole struct {
	Name          string   `json:"name"`
	CertSubjectDN string   `json:"cert_subject_dn"`
	AllowedOps    []string `json:"allowed_ops"`
}

func (b *backend) pathKmipRoles() *framework.Path {
	return &framework.Path{
		Pattern: "kmip/roles/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "kmip-role",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the KMIP role.",
			},
			"cert_subject_dn": {
				Type:        framework.TypeString,
				Description: "Distinguished Name (DN) of the client certificate subject that maps to this role.",
			},
			"allowed_operations": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of KMIP operations this role is permitted to perform (e.g. Create, Get, Locate, Destroy).",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleRead,
				Summary:  "Read a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "read",
					OperationSuffix: "kmip-role",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleWrite,
				Summary:  "Create or update a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "write",
					OperationSuffix: "kmip-role",
				},
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleWrite,
				Summary:  "Create or update a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "create",
					OperationSuffix: "kmip-role",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleDelete,
				Summary:  "Delete a KMIP role.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "delete",
					OperationSuffix: "kmip-role",
				},
			},
		},

		HelpSynopsis:    pathKmipRoleHelpSyn,
		HelpDescription: pathKmipRoleHelpDesc,
	}
}

func (b *backend) pathKmipRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "kmip/roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
			OperationSuffix: "kmip-roles",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathKmipRoleListAll,
				Summary:  "List all KMIP roles.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "list",
					OperationSuffix: "kmip-roles",
				},
			},
		},

		HelpSynopsis:    pathKmipRoleListHelpSyn,
		HelpDescription: pathKmipRoleListHelpDesc,
	}
}

func (b *backend) pathKmipRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getKmipRole(ctx, req.Storage, name)
	if err != nil || role == nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"cert_subject_dn":    role.CertSubjectDN,
			"allowed_operations": role.AllowedOps,
		},
	}, nil
}

func (b *backend) pathKmipRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.kmipMu.Lock()
	defer b.kmipMu.Unlock()

	name := d.Get("name").(string)

	// Load existing role to allow partial updates
	role, err := b.getKmipRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &kmipRole{}
	}

	if v, ok := d.GetOk("cert_subject_dn"); ok {
		newDN := v.(string)
		if newDN == "" {
			return logical.ErrorResponse("cert_subject_dn is required"), logical.ErrInvalidRequest
		}

		// Reject if another role already claims this Subject DN.
		existing, err := b.findKmipRoleByDN(ctx, req.Storage, newDN)
		if err != nil {
			return nil, err
		}
		if existing != nil && role.CertSubjectDN != newDN {
			return logical.ErrorResponse("cert_subject_dn %q is already claimed by another role", newDN), nil
		}
		role.CertSubjectDN = newDN
	}

	if v, ok := d.GetOk("allowed_operations"); ok {
		ops := v.([]string)
		for _, op := range ops {
			if !kmip.IsValidOperation(op) {
				return logical.ErrorResponse("invalid KMIP operation %q, valid operations are: %v", op, kmip.ValidOperations()), logical.ErrInvalidRequest
			}
		}
		role.AllowedOps = ops
	}

	entry, err := logical.StorageEntryJSON(kmip.RoleStoragePrefix+name, role)
	if err != nil {
		return nil, err
	}

	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathKmipRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	return nil, req.Storage.Delete(ctx, kmip.RoleStoragePrefix+name)
}

func (b *backend) pathKmipRoleListAll(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, kmip.RoleStoragePrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) getKmipRole(ctx context.Context, s logical.Storage, name string) (*kmipRole, error) {
	entry, err := s.Get(ctx, kmip.RoleStoragePrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}

	var role kmipRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding KMIP role %q: %w", name, err)
	}
	return &role, nil
}

func (b *backend) findKmipRoleByDN(ctx context.Context, s logical.Storage, dn string) (*kmipRole, error) {
	if s == nil {
		return nil, nil
	}

	names, err := s.List(ctx, kmip.RoleStoragePrefix)
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		role, err := b.getKmipRole(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if role != nil && role.CertSubjectDN == dn {
			return role, nil
		}
	}

	return nil, nil
}

const pathKmipRoleHelpSyn = `Manage KMIP roles that map client certificate Subject DNs to allowed operations`

const pathKmipRoleHelpDesc = `
A KMIP role maps a client certificate Subject Distinguished Name (DN) to a set
of allowed KMIP operations. When a KMIP client connects with mTLS, the transit
KMIP server uses the client certificate's Subject DN to
look up the corresponding role and authorize or reject the requested operation.
`

const pathKmipRoleListHelpSyn = `List all configured KMIP roles`

const pathKmipRoleListHelpDesc = `
List all KMIP roles configured for this transit mount.
`
