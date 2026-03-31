package vault

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/profiles"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
)

const (
	workflowSubPath   = "workflows/"
	workflowOuterName = "flow"
)

type WorkflowEntry struct {
	Path                 string `json:"-"`
	Workflow             string `json:"workflow"`
	Description          string `json:"description"`
	Version              int    `json:"version"`
	CASRequired          bool   `json:"cas_required"`
	AllowUnauthenticated bool   `json:"allow_unauthenticated"`
}

func (we *WorkflowEntry) Parse(ctx context.Context) (*profiles.InputConfig, []*profiles.OuterConfig, *profiles.OutputConfig, error) {
	var input *profiles.InputConfig
	var profile []*profiles.OuterConfig
	var output *profiles.OutputConfig

	obj, err := hcl.Parse(we.Workflow)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed during HCL parsing: %w", err)
	}

	list, ok := obj.Node.(*ast.ObjectList)
	if !ok {
		return nil, nil, nil, errors.New("workflow doesn't contain a root object")
	}

	if o := list.Filter("input"); len(o.Items) > 0 {
		input, err = profiles.ParseInputConfig(o)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse input configuration block: %w", err)
		}
	}

	if o := list.Filter(workflowOuterName); len(o.Items) > 0 {
		profile, err = profiles.ParseOuterConfig(workflowOuterName, o)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse workflow: %w", err)
		}
	}

	if o := list.Filter("output"); len(o.Items) > 0 {
		output, err = profiles.ParseOutputConfig(o)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse output configuration block: %w", err)
		}
	}

	if len(profile) == 0 {
		return nil, nil, nil, fmt.Errorf("workflow must have at least one %q block", workflowOuterName)
	}

	return input, profile, output, nil
}

type WorkflowStore struct {
	core   *Core
	lock   sync.RWMutex
	logger log.Logger
}

func NewWorkflowStore(c *Core) *WorkflowStore {
	logger := c.baseLogger.Named("profile")
	return &WorkflowStore{
		core:   c,
		logger: logger,
	}
}

func (c *Core) setupWorkflowStore(ctx context.Context) {
	c.workflowStore = NewWorkflowStore(c)
}

// getView returns the storage view for the given namespace
func (ws *WorkflowStore) getView(ns *namespace.Namespace) barrier.View {
	return NamespaceScopedView(ws.core.barrier, ns).SubView(workflowSubPath)
}

func (ws *WorkflowStore) Get(ctx context.Context, path string) (*WorkflowEntry, error) {
	ws.lock.RLock()
	defer ws.lock.RUnlock()

	return ws.getLocked(ctx, path)
}

func (ws *WorkflowStore) getLocked(ctx context.Context, path string) (*WorkflowEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	path = ws.sanitizePath(path)
	view := ws.getView(ns)

	entry, err := view.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	var workflow WorkflowEntry
	if err := entry.DecodeJSON(&workflow); err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	workflow.Path = path

	return &workflow, nil
}

func (ws *WorkflowStore) Set(ctx context.Context, workflow *WorkflowEntry, casVersion *int) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	path := ws.sanitizePath(workflow.Path)
	view := ws.getView(ns)

	ws.lock.Lock()
	defer ws.lock.Unlock()

	existing, err := ws.getLocked(ctx, workflow.Path)
	if err != nil {
		return err
	}

	casRequired := (existing != nil && existing.CASRequired) || workflow.CASRequired
	if casVersion == nil && casRequired {
		return fmt.Errorf("check-and-set parameter required for this call")
	}
	if casVersion != nil {
		if *casVersion == -1 && existing != nil {
			return fmt.Errorf("check-and-set parameter set to -1 on existing entry")
		}

		if *casVersion != -1 && existing == nil {
			return fmt.Errorf("check-and-set parameter set greater than 1 on non-existent entry")
		}

		if *casVersion != -1 && *casVersion != existing.Version {
			return fmt.Errorf("check-and-set parameter did not match the current version")
		}
	}

	workflow.Version = 1
	if existing != nil {
		workflow.Version += existing.Version
	}

	entry, err := logical.StorageEntryJSON(path, workflow)
	if err != nil {
		return fmt.Errorf("failed to encode workflow: %w", err)
	}

	if err := view.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write workflow: %w", err)
	}

	return nil
}

func (ws *WorkflowStore) Delete(ctx context.Context, path string) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	path = ws.sanitizePath(path)
	view := ws.getView(ns)

	ws.lock.Lock()
	defer ws.lock.Unlock()

	return view.Delete(ctx, path)
}

func (ws *WorkflowStore) List(ctx context.Context, prefix string, recursive bool, after string, limit int) ([]*WorkflowEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	prefix = ws.sanitizePath(prefix)
	view := ws.getView(ns)
	view = view.SubView(prefix)

	ws.lock.RLock()
	defer ws.lock.RUnlock()

	var keys []string
	if !recursive {
		keys, err = view.ListPage(ctx, "", after, limit)
	} else {
		err = logical.ScanView(ctx, view, func(path string) {
			keys = append(keys, path)
		})
	}

	if err != nil {
		return nil, err
	}

	var results []*WorkflowEntry
	for index, key := range keys {
		path := filepath.Join(prefix, key)
		entry, err := ws.getLocked(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch workflow (%d/%v) in list: %w", index, path, err)
		}

		results = append(results, entry)
	}

	return results, nil
}

func (ws *WorkflowStore) Execute(ctx context.Context, path string, unauthed bool, trace bool, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to find namespace in context: %w", err)
	}

	ws.lock.RLock()
	defer ws.lock.RUnlock()

	workflow, err := ws.getLocked(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to execute workflow: %w", err)
	}

	// Prefer permission denied for missing workflows when unauthenticated.
	if unauthed && (workflow == nil || !workflow.AllowUnauthenticated) {
		return nil, logical.ErrPermissionDenied
	}

	if workflow == nil {
		return nil, nil
	}

	input, contents, output, err := workflow.Parse(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	engine, err := profiles.NewEngine(
		// Do not allow sources which could bypass authorization.
		profiles.WithRequestSource(),
		profiles.WithResponseSource(),
		profiles.WithTemplateSource(),
		profiles.WithInputSource(input, req, data),
		profiles.WithOutput(output),

		// Name of our outer block; this is called context.
		profiles.WithOuterBlockName(workflowOuterName),

		// The actual profile we're trying to execute.
		profiles.WithProfile(contents),

		// Default token to use.
		profiles.WithDefaultToken(req.ClientToken),

		// Execute our request handler here; here is where we validate that
		// this policy can only access requests under its own namespace and
		// forbid requests to parent namespaces.
		profiles.WithRequestHandler(func(ctx context.Context, req *logical.Request) (*logical.Response, error) {
			// When a namespace header exists in the synthetic request, we
			// have to inject it into the namespace header, ensuring we set
			// the prefix accordingly.
			if values, ok := req.Headers[consts.NamespaceHeaderName]; ok {
				if len(values) > 1 {
					return nil, fmt.Errorf("have %q values for %q header; expected only 1", len(values), consts.NamespaceHeaderName)
				}

				nsHeader := namespace.HeaderFromContext(ctx)
				nsHeader = filepath.Join(nsHeader, values[0])
				ctx = namespace.ContextWithNamespaceHeader(ctx, nsHeader)
			}

			// We guarantee we come in from the profile system, which means
			// we're already executing a request; no need to re-grab the lock
			// here.
			return ws.core.switchedLockHandleRequest(ctx, req, false)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed building profile engine: %w", err)
	}

	// HandleRequest will force all requests with a given namespace to be
	// routed to the namespace in the context, even if the request path has
	// a different namespace.
	noNsCtx := namespace.ContextWithNamespace(ctx, nil)
	noNsCtx = namespace.ContextWithNamespaceHeader(noNsCtx, ns.Path)

	if trace {
		result := engine.Debug(noNsCtx)
		return &logical.Response{
			Data: result,
		}, nil
	}

	if output != nil {
		return engine.EvaluateResponse(noNsCtx)
	}

	if err := engine.Evaluate(noNsCtx); err != nil {
		return nil, fmt.Errorf("failed to evaluate namespace: %w", err)
	}

	return nil, nil
}

func (ws *WorkflowStore) sanitizePath(path string) string {
	return strings.ToLower(strings.TrimSpace(path))
}
