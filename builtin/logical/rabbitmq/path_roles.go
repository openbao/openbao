// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rabbitmq

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixRabbitMQ,
			OperationSuffix: "roles",
		},

		Fields: map[string]*framework.FieldSchema{
			"after": {
				Type:        framework.TypeString,
				Description: `Optional entry to list begin listing after, not required to exist.`,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: `Optional number of entries to return; defaults to all entries.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleList,
			},
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixRabbitMQ,
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"tags": {
				Type:        framework.TypeString,
				Description: "Comma-separated list of tags for this role.",
			},
			"vhosts": {
				Type:        framework.TypeString,
				Description: "A map of virtual hosts to permissions.",
			},
			"vhost_topics": {
				Type:        framework.TypeString,
				Description: "A nested map of virtual hosts and exchanges to topic permissions.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleUpdate,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
		},
		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

// Reads the role configuration from the storage
func (b *backend) Role(ctx context.Context, s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Deletes an existing role
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	return nil, req.Storage.Delete(ctx, "role/"+name)
}

// Reads an existing role
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := map[string]interface{}{}
	resp["tags"] = role.Tags
	respVHost := map[string]interface{}{}
	for key, value := range role.VHosts {
		respVHost[key] = map[string]interface{}{
			"configure": value.Configure,
			"write":     value.Write,
			"read":      value.Read,
		}
	}
	resp["vhosts"] = respVHost

	respVHostTopics := map[string]interface{}{}
	for key, topic := range role.VHostTopics {
		respVHostTopic := map[string]interface{}{}
		for topicKey, value := range topic {
			respVHostTopic[topicKey] = map[string]interface{}{
				"write": value.Write,
				"read":  value.Read,
			}
		}
		respVHostTopics[key] = respVHostTopic
	}
	resp["vhost_topics"] = respVHostTopics

	return &logical.Response{
		Data: resp,
	}, nil
}

// Lists all the roles registered with the backend
func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	roles, err := req.Storage.ListPage(ctx, "role/", after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

// Registers a new role with the backend
func (b *backend) pathRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	tags := d.Get("tags").(string)
	rawVHosts := d.Get("vhosts").(string)
	rawVHostTopics := d.Get("vhost_topics").(string)

	// Either tags or VHost permissions are always required, but topic permissions are always optional.
	if tags == "" && rawVHosts == "" {
		return logical.ErrorResponse("both tags and vhosts not specified"), nil
	}

	var vhosts map[string]vhostPermission
	if len(rawVHosts) > 0 {
		if err := jsonutil.DecodeJSON([]byte(rawVHosts), &vhosts); err != nil {
			return logical.ErrorResponse("failed to unmarshal vhosts: %s", err), nil
		}
	}

	var vhostTopics map[string]map[string]vhostTopicPermission
	if len(rawVHostTopics) > 0 {
		if err := jsonutil.DecodeJSON([]byte(rawVHostTopics), &vhostTopics); err != nil {
			return logical.ErrorResponse("failed to unmarshal vhost_topics: %s", err), nil
		}
	}

	// Store it
	entry, err := logical.StorageEntryJSON("role/"+name, &roleEntry{
		Tags:        tags,
		VHosts:      vhosts,
		VHostTopics: vhostTopics,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// Role that defines the capabilities of the credentials issued against it.
// Maps are used because the names of vhosts and exchanges will vary widely.
// VHosts is a map with a vhost name as key and the permissions as value.
// VHostTopics is a nested map with vhost name and exchange name as keys and
// the topic permissions as value.
type roleEntry struct {
	Tags        string                                     `json:"tags" structs:"tags" mapstructure:"tags"`
	VHosts      map[string]vhostPermission                 `json:"vhosts" structs:"vhosts" mapstructure:"vhosts"`
	VHostTopics map[string]map[string]vhostTopicPermission `json:"vhost_topics" structs:"vhost_topics" mapstructure:"vhost_topics"`
}

// Structure representing the permissions of a vhost
type vhostPermission struct {
	Configure string `json:"configure" structs:"configure" mapstructure:"configure"`
	Write     string `json:"write" structs:"write" mapstructure:"write"`
	Read      string `json:"read" structs:"read" mapstructure:"read"`
}

// Structure representing the topic permissions of an exchange
type vhostTopicPermission struct {
	Write string `json:"write" structs:"write" mapstructure:"write"`
	Read  string `json:"read" structs:"read" mapstructure:"read"`
}

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`

const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

The "tags" parameter customizes the tags used to create the role.
This is a comma separated list of strings. The "vhosts" parameter customizes
the virtual hosts that this user will be associated with. This is a JSON object
passed as a string in the form:
{
	"vhostOne": {
		"configure": ".*",
		"write": ".*",
		"read": ".*"
	},
	"vhostTwo": {
		"configure": ".*",
		"write": ".*",
		"read": ".*"
	}
}
The "vhost_topics" parameter customizes the topic permissions that this user
will be granted. This is a JSON object passed as a string in the form:
{
	"vhostOne": {
		"exchangeOneOne": {
			"write": ".*",
			"read": ".*"
		},
		"exchangeOneTwo": {
			"write": ".*",
			"read": ".*"
		}
	},
	"vhostTwo": {
		"exchangeTwoOne": {
			"write": ".*",
			"read": ".*"
		}
	}
}
`
