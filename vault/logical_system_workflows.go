// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"net/http"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) workflowPaths() []*framework.Path {
	workflowListSchema := map[string]*framework.FieldSchema{
		"keys": {
			Type:        framework.TypeStringSlice,
			Description: "List of workflow paths.",
		},
		"key_info": {
			Type:        framework.TypeMap,
			Description: "Map of workflow details by path.",
		},
	}

	workflowSchema := map[string]*framework.FieldSchema{
		"description": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Workflow description.",
		},
		"workflow": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Workflow definition in HCL or JSON.",
		},
		"version": {
			Type:        framework.TypeInt,
			Required:    true,
			Description: "Version of the workflow.",
		},
		"cas_required": {
			Type:        framework.TypeBool,
			Required:    true,
			Description: "Whether check and set support is required.",
		},
		"allow_unauthenticated": {
			Type:        framework.TypeBool,
			Required:    true,
			Description: "Whether this workflow can be accessed unauthenticated.",
		},
	}

	paths := []*framework.Path{
		{
			Pattern: "workflows/manage/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows",
			},

			Fields: map[string]*framework.FieldSchema{
				"after": {
					Type:        framework.TypeString,
					Description: "Optional entry to begin listing after; not required to exist.",
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: "Optional number of entries to return; defaults to all entries.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsList(false),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsList(true),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["list-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["list-workflows"][1]),
		},

		{
			Pattern: "workflows/manage/(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the workflow.",
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Workflow description.",
				},
				"workflow": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Workflow definition in either HCL or JSON format.",
				},
				"cas": {
					Type:        framework.TypeInt,
					Description: "Check and set version of the workflow.",
				},
				"cas_required": {
					Type:        framework.TypeBool,
					Description: "Whether to require check and set for modifying this workflow.",
				},
				"allow_unauthenticated": {
					Type:        framework.TypeBool,
					Description: "Whether this workflow can be executed unauthenticated. Use with care.",
				},
				"after": {
					Type:        framework.TypeString,
					Description: "Optional entry to begin listing after; not required to exist.",
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: "Optional number of entries to return; defaults to all entries.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsRead(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowSchema}},
					},
					Summary: "Retrieve a workflow.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsUpdate(),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowSchema}},
					},
					Summary: "Create or update a workflow.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsDelete(),
					Responses: map[int][]framework.Response{
						http.StatusNoContent: {{Description: "No Content"}},
					},
					Summary: "Delete a workflow.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsList(false),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsList(true),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["workflows"][1]),
		},

		{
			Pattern: "workflows/execute/(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows-execute",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the workflow.",
				},
			},
			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecute(false /* we are authenticated */, false /* we are doing a real execution */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK"}},
					},
					Summary: "Execute the given workflow.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["exec-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["exec-workflows"][1]),
		},

		{
			Pattern: "workflows/trace/(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows-trace",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the workflow.",
				},
			},
			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecute(false /* we are authenticated */, true /* we are executing in trace mode */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK"}},
					},
					Summary: "Execute the given workflow.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["exec-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["exec-workflows"][1]),
		},
	}

	if b.Core.allowUnauthedWorkflows {
		paths = append(paths, &framework.Path{
			Pattern: "workflows/unauthed-execute/(?P<path>.+)",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows-unauthed-execute",
			},

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path of the workflow.",
				},
			},
			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecute(true /* we are unauthenticated */, false /* we are not performing a trace */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK"}},
					},
					Summary: "Execute the given workflow without authentication.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["exec-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["exec-workflows"][1]),
		})
	}

	return paths
}

func createWorkflowListResponse(we *WorkflowEntry) map[string]any {
	return map[string]any{
		"path":                  we.Path,
		"version":               we.Version,
		"cas_required":          we.CASRequired,
		"allow_unauthenticated": we.AllowUnauthenticated,
		"description":           we.Description,
	}
}

func createWorkflowDataResponse(we *WorkflowEntry) map[string]any {
	base := createWorkflowListResponse(we)
	base["workflow"] = we.Workflow
	return base
}

// handleWorkflowsList handles "/sys/workflows/manage/*" endpoints to list the
// workflows.
func (b *SystemBackend) handleWorkflowsList(scan bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		parent := ""
		if _, present := data.Schema["path"]; present {
			parent = data.Get("parent").(string)
		}

		after := data.Get("after").(string)
		limit := data.Get("limit").(int)

		workflows, err := b.Core.workflowStore.List(ctx, parent, scan, after, limit)
		if err != nil {
			return nil, err
		}

		keys := make([]string, 0, len(workflows))
		keyInfo := make(map[string]any, len(workflows))
		for _, entry := range workflows {
			keys = append(keys, entry.Path)
			keyInfo[entry.Path] = createWorkflowDataResponse(entry)
		}

		return logical.ListResponseWithInfo(keys, keyInfo), nil
	}
}

// handleWorkflowsRead handles the "/sys/workflows/manage/<path>" endpoints to read a
// workflow.
func (b *SystemBackend) handleWorkflowsRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		pe, err := b.Core.workflowStore.Get(ctx, path)
		if err != nil {
			return handleError(err)
		}
		if pe == nil {
			return nil, nil
		}

		return &logical.Response{Data: createWorkflowDataResponse(pe)}, nil
	}
}

// handleWorkflowsUpdate handles the "/sys/workflows/manage/<path>" endpoint to
// update a workflow.
func (b *SystemBackend) handleWorkflowsUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		var cas *int
		casRaw, ok := data.GetOk("cas")
		if ok {
			cas := new(int)
			*cas = casRaw.(int)
		}

		workflow := data.Get("workflow").(string)
		description := data.Get("description").(string)
		allowUnauthenticated := data.Get("allow_unauthenticated").(bool)
		casRequired := data.Get("cas_required").(bool)

		pe := &WorkflowEntry{
			Path:                 path,
			Workflow:             workflow,
			Description:          description,
			CASRequired:          casRequired,
			AllowUnauthenticated: allowUnauthenticated,
		}

		err := b.Core.workflowStore.Set(ctx, pe, cas)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{Data: createWorkflowDataResponse(pe)}, nil
	}
}

// handleWorkflowsDelete handles the "/sys/workflow/<path>" endpoint to delete a workflow.
func (b *SystemBackend) handleWorkflowsDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		err := b.Core.workflowStore.Delete(ctx, path)
		return nil, err
	}
}

// handleWorkflowsExecute handles the "/sys/workflow/execute/<path>" and
// "/sys/workflow/unauthed-execute/<path>" endpoints to execute workflows.
func (b *SystemBackend) handleWorkflowsExecute(unauthed bool, trace bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		if unauthed {
			trace = false
		}

		return b.Core.workflowStore.Execute(ctx, path, unauthed, trace, req, data)
	}
}
