// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *SystemBackend) workflowPaths() []*framework.Path {
	workflowManageListSchema := map[string]*framework.FieldSchema{
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

	workflowExecuteListSchema := map[string]*framework.FieldSchema{
		"keys": {
			Type:        framework.TypeStringSlice,
			Description: "List of workflow paths.",
		},
	}

	workflowExecutionReadSchema := map[string]*framework.FieldSchema{
		"path": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Path of the workflow.",
		},
		"description": {
			Type:        framework.TypeString,
			Required:    true,
			Description: "Workflow description.",
		},
		"allow_unauthenticated": {
			Type:        framework.TypeBool,
			Required:    true,
			Description: "Whether this workflow can be accessed unauthenticated.",
		},
		"inputs": {
			Type:        framework.TypeStringSlice,
			Description: "Declared input fields, as \"name <type>\".",
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
					Callback: b.handleWorkflowsManageList(false),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowManageListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsManageList(true),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowManageListSchema}},
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
				logical.ResolvePathOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsResolvePath("workflows/manage/"),
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsManageRead(),
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
					Callback: b.handleWorkflowsManageList(false),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowManageListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsManageList(true),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowManageListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["workflows"][1]),
		},

		{
			Pattern: "workflows/execute/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows-execute",
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
					Callback: b.handleWorkflowsExecuteList(false, false /* we are authed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteList(true, false /* we are authed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["list-exec-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["list-exec-workflows"][1]),
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
				"after": {
					Type:        framework.TypeString,
					Description: "Optional entry to begin listing after; not required to exist.",
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: "Optional number of entries to return; defaults to all entries.",
				},
			},
			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ResolvePathOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsResolvePath("workflows/execute/"),
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteRead(false /* we are authenticated */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecutionReadSchema}},
					},
					Summary: "Retrieve information relevant to the execution of the given workflow.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecute(false /* we are authenticated */, false /* we are doing a real execution */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK"}},
					},
					Summary: "Execute the given workflow.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteList(false, false /* we are authed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteList(true, false /* we are authed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["execute-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["execute-workflows"][1]),
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
				logical.ResolvePathOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsResolvePath("workflows/trace/"),
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecute(false /* we are authenticated */, true /* we are executing in trace mode */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK"}},
					},
					Summary: "Execute the given workflow.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["trace-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["trace-workflows"][1]),
		},
	}

	if b.Core.allowUnauthedWorkflows {
		paths = append(paths, &framework.Path{
			Pattern: "workflows/unauthed-execute/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "workflows-unauthed-execute",
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
					Callback: b.handleWorkflowsExecuteList(false, true /* we are unauthed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteList(true, true /* we are unauthed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["unauthed-exec-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["unauthed-exec-workflows"][1]),
		}, &framework.Path{
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
				"after": {
					Type:        framework.TypeString,
					Description: "Optional entry to begin listing after; not required to exist.",
				},
				"limit": {
					Type:        framework.TypeInt,
					Description: "Optional number of entries to return; defaults to all entries.",
				},
			},
			TakesArbitraryInput: true,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ResolvePathOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsResolvePath("workflows/unauthed-execute/"),
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteRead(true /* we are unauthenticated */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecutionReadSchema}},
					},
					Summary: "Retrieve information relevant to the execution of the given workflow.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecute(true /* we are unauthenticated */, false /* we are not performing a trace */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK"}},
					},
					Summary: "Execute the given workflow without authentication.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteList(false, true /* we are unauthed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "List workflows.",
				},
				logical.ScanOperation: &framework.PathOperation{
					Callback: b.handleWorkflowsExecuteList(true, true /* we are unauthed */),
					Responses: map[int][]framework.Response{
						http.StatusOK: {{Description: "OK", Fields: workflowExecuteListSchema}},
					},
					Summary: "Scan (recursively list) workflows.",
				},
			},

			HelpSynopsis:    strings.TrimSpace(sysHelp["unauthed-exec-workflows"][0]),
			HelpDescription: strings.TrimSpace(sysHelp["unauthed-exec-workflows"][1]),
		})
	}

	return paths
}

func createWorkflowExecuteReadResponse(we *WorkflowEntry, ctx context.Context) (map[string]any, error) {
	inputs, _, _, err := we.Parse(ctx)
	if err != nil {
		return nil, err
	}
	workflowData := map[string]any{
		"path":                  we.Path,
		"description":           we.Description,
		"allow_unauthenticated": we.AllowUnauthenticated,
	}
	if inputs != nil {
		inputInfos := make([]string, len(inputs.Fields))
		for i, input := range inputs.Fields {
			inputInfo := fmt.Sprintf("%s <%s>", input.Name, input.Type.String())
			inputInfos[i] = inputInfo
		}
		workflowData["inputs"] = inputInfos
	}
	return workflowData, nil
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

func (b *SystemBackend) handleWorkflowsResolvePath(prefix string) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		path = b.Core.workflowStore.sanitizePath(path)

		if strings.HasSuffix(req.Path, "/") {
			// GenericNameRegex does not include the trailing '/' present when
			// listing a subset of policies.
			path += "/"
		}

		return logical.ResolvePathResponse(prefix + path)
	}
}

// handleWorkflowsManageList handles "/sys/workflows/manage/*" endpoints to list the
// workflows. This includes privileged information like the version, cas required and the workflow itself.
func (b *SystemBackend) handleWorkflowsManageList(scan bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		parent := ""
		if _, present := data.Schema["path"]; present {
			parent = data.Get("path").(string)
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
			if strings.HasSuffix(entry.Path, "/") {
				continue
			}
			keyInfo[entry.Path] = createWorkflowDataResponse(entry)
		}

		return logical.ListResponseWithInfo(keys, keyInfo), nil
	}
}

// handleWorkflowsManageRead handles the "/sys/workflows/manage/<path>" endpoints to read a
// workflow. This includes privileged information like the version, cas required and the workflow itself.
func (b *SystemBackend) handleWorkflowsManageRead() framework.OperationFunc {
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
			cas = new(int)
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

		if _, _, _, err := pe.Parse(ctx); err != nil {
			return handleError(err)
		}

		err := b.Core.workflowStore.Set(ctx, pe, cas)
		if err != nil {
			return handleError(err)
		}

		return &logical.Response{Data: createWorkflowDataResponse(pe)}, nil
	}
}

// handleWorkflowsDelete handles the "/sys/workflows/<path>" endpoint to delete a workflow.
func (b *SystemBackend) handleWorkflowsDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)

		err := b.Core.workflowStore.Delete(ctx, path)
		return nil, err
	}
}

// handleWorkflowsExecuteRead handles the "/sys/workflows/execute/<path>" and "/sys/workflows/unauthed-execute/<path>" endpoints
// to read execution relevant information. This information includes the path, description, allow unauthenticated and the inputs.
func (b *SystemBackend) handleWorkflowsExecuteRead(unauthed bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		pe, err := b.Core.workflowStore.Get(ctx, path)
		if err != nil {
			return handleError(err)
		}
		if unauthed && (pe == nil || !pe.AllowUnauthenticated) {
			return nil, logical.ErrPermissionDenied
		}
		if pe == nil {
			return nil, nil
		}
		workflowData, err := createWorkflowExecuteReadResponse(pe, ctx)
		if err != nil {
			return handleError(err)
		}
		return &logical.Response{Data: workflowData}, nil
	}
}

// handleWorkflowsExecuteList handles the LIST operation for the "/sys/workflows/execute" and "/sys/workflows/unauthed-execute/"
// endpoint to list the workflow. This outputs only the keys (paths) from the workflows.
func (b *SystemBackend) handleWorkflowsExecuteList(scan bool, unauthed bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		parent := ""
		if _, present := data.Schema["path"]; present {
			parent = data.Get("path").(string)
		}

		after := data.Get("after").(string)
		limit := data.Get("limit").(int)

		workflows, err := b.Core.workflowStore.List(ctx, parent, scan, after, limit)
		if err != nil {
			return nil, err
		}

		keys := make([]string, 0, len(workflows))
		for _, entry := range workflows {
			if unauthed && !entry.AllowUnauthenticated {
				continue
			}
			keys = append(keys, entry.Path)
		}

		return logical.ListResponse(keys), nil
	}
}

// handleWorkflowsExecute handles the "/sys/workflows/execute/<path>" and
// "/sys/workflows/unauthed-execute/<path>" endpoints to execute workflows.
func (b *SystemBackend) handleWorkflowsExecute(unauthed bool, trace bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		path := data.Get("path").(string)
		return b.Core.workflowStore.Execute(ctx, req.ID, path, unauthed, trace, req, data)
	}
}
