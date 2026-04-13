package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	urlpath "path"
	"path/filepath"
	"strings"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/profiles"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/vault/barrier"
)

const (
	workflowSubPath   = "workflows/"
	workflowOuterName = "flow"

	maxWorkflowRecursion = 5
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
	core        *Core
	modifyLocks []*locksutil.LockEntry
	logger      log.Logger
}

func NewWorkflowStore(c *Core) *WorkflowStore {
	logger := c.baseLogger.Named("workflow")
	return &WorkflowStore{
		core:        c,
		modifyLocks: locksutil.CreateLocks(),
		logger:      logger,
	}
}

func (c *Core) setupWorkflowStore(ctx context.Context) {
	c.workflowStore = NewWorkflowStore(c)
}

func (ws *WorkflowStore) lockWithUnlock(ctx context.Context) func() {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		ns = namespace.RootNamespace
	}

	lock := locksutil.LockForKey(ws.modifyLocks, ns.UUID)

	ws.logger.Trace("acquiring lock for", "namespace", ns.UUID)
	lock.Lock()
	return lock.Unlock
}

func (ws *WorkflowStore) rLockWithUnlock(ctx context.Context) func() {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		ns = namespace.RootNamespace
	}

	lock := locksutil.LockForKey(ws.modifyLocks, ns.UUID)

	ws.logger.Trace("acquiring lock for", "namespace", ns.UUID)
	lock.RLock()
	return lock.RUnlock
}

// getView returns the storage view for the given namespace
func (ws *WorkflowStore) getView(ns *namespace.Namespace) barrier.View {
	return NamespaceScopedView(ws.core.barrier, ns).SubView(workflowSubPath)
}

func (ws *WorkflowStore) Get(ctx context.Context, path string) (*WorkflowEntry, error) {
	// Check namespace existence before calling RLock().
	_, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	defer ws.rLockWithUnlock(ctx)()
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

	defer ws.lockWithUnlock(ctx)()

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

	defer ws.lockWithUnlock(ctx)()

	return view.Delete(ctx, path)
}

func (ws *WorkflowStore) List(ctx context.Context, prefix string, recursive bool, after string, limit int) ([]*WorkflowEntry, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	prefix = ws.sanitizePath(prefix)
	view := ws.getView(ns).SubView(prefix)

	defer ws.rLockWithUnlock(ctx)()

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

func (ws *WorkflowStore) Execute(ctx context.Context, reqId string, path string, unauthed bool, trace bool, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to find namespace in context: %w", err)
	}

	// Reject trace requests when unauthenticated.
	if unauthed && trace {
		return nil, logical.ErrPermissionDenied
	}

	workflow, err := func() (*WorkflowEntry, error) {
		defer ws.rLockWithUnlock(ctx)()
		return ws.getLocked(ctx, path)
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to execute workflow: %w", err)
	}

	// Prefer permission denied for missing workflows when unauthenticated.
	if unauthed && (workflow == nil || !workflow.AllowUnauthenticated) {
		return nil, logical.ErrPermissionDenied
	}

	if workflow == nil {
		return nil, logical.CodedError(http.StatusNotFound, "workflow does not exist")
	}

	// Reject recursive calls starting from an unauthenticated workflow. That
	// is, don't allow a call like:
	//
	// unauthed -> unauthed
	// unauthed -> authed
	//
	// However, recursive calls like authed -> unauthed are allowed (though,
	// cannot subsequently call another profile!) or the recursive authed
	// chain of authed -> authed [ -> authed ].
	if strings.Contains(reqId, ".unauthed.workflow.") {
		return nil, logical.ErrPermissionDenied
	}

	// Similarly, set a maximum limit on authenticated recursion based on
	// number of workflows in the request identifier.
	if strings.Count(reqId, ".workflow.") == maxWorkflowRecursion {
		return nil, logical.CodedError(http.StatusBadRequest, "too much workflow recursion")
	}

	input, contents, output, err := workflow.Parse(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	authedStr := "authed"
	if unauthed {
		authedStr = "unauthed"
	}

	engine, err := profiles.NewEngine(
		// Do not allow sources which could bypass authorization.
		profiles.WithRequestSource(),
		profiles.WithResponseSource(),
		profiles.WithCELSource(),
		profiles.WithTemplateSource(),
		profiles.WithInputSource(input, req, data),
		profiles.WithOutput(output),

		// Name of our outer block; this is called context.
		profiles.WithOuterBlockName(workflowOuterName),

		// The actual profile we're trying to execute.
		profiles.WithProfile(contents),

		// Default token to use.
		profiles.WithDefaultToken(req.ClientToken),

		// Allow auditing our generated requests by tying this to the input
		// API request. When handling recursive requests, this could get
		// long.
		profiles.WithRequestIdentifierPrefix(fmt.Sprintf("%v.%v.workflow.%v", reqId, authedStr, path)),

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
				nsHeader = urlpath.Join(nsHeader, values[0])
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
		return nil, fmt.Errorf("failed to evaluate workflow: %w", err)
	}

	// Return 200 OK with no associated data rather than 204 to keep the
	// success conditions consistent.
	return &logical.Response{}, nil
}

func (ws *WorkflowStore) sanitizePath(path string) string {
	return strings.ToLower(strings.TrimSpace(path))
}
