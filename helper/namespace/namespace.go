// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package namespace

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

// reservedNames is the list of string names that
// shouldn't be used as namespace name, hence are forbidden to use
var reservedNames = []string{
	"",
	".",
	"..",
	"root",
	"sys",
	"audit",
	"auth",
	"cubbyhole",
	"identity",
}

type (
	contextKeyNamespace struct{}
	contextKeyHeader    struct{}
)

type Namespace struct {
	ID             string            `json:"id" mapstructure:"id"`
	UUID           string            `json:"uuid" mapstructure:"uuid"`
	Path           string            `json:"path" mapstructure:"path"`
	Tainted        bool              `json:"tainted" mapstructure:"tainted"`
	Locked         bool              `json:"-"`
	UnlockKey      string            `json:"unlock_key" mapstructure:"unlock_key"`
	CustomMetadata map[string]string `json:"custom_metadata" mapstructure:"custom_metadata"`
}

func (n *Namespace) String() string {
	return fmt.Sprintf("ID: %s. Path: %s", n.ID, n.Path)
}

func (n *Namespace) Validate() error {
	n.Path = Canonicalize(n.Path)
	if n.Path == "" {
		return errors.New("path is missing; cannot validate root namespace")
	}

	if n.ID == RootNamespaceID {
		return errors.New("cannot reuse root namespace identifier")
	}

	// canonicalize adds a trailing slash, we don't need to consider it here
	for segment := range strings.SplitSeq(n.Path[:len(n.Path)-1], "/") {
		if segment == "" {
			return fmt.Errorf("namespace name cannot be empty")
		}
		if slices.Contains(reservedNames, segment) {
			return fmt.Errorf("%q is a reserved path and cannot be used as a namespace name", segment)
		}

		for _, r := range segment {
			switch {
			case !utf8.ValidRune(r):
				return fmt.Errorf("%q contains invalid utf-8 characters that cannot be used in a namespace name: %q", segment, r)
			case !unicode.IsGraphic(r):
				return fmt.Errorf("%q contains unicode characters that cannot be used in a namespace name: %q", segment, r)
			case unicode.IsSpace(r):
				return fmt.Errorf("%q contains space characters that cannot be used in a namespace name", segment)
			case r == '+' || r == '*':
				return fmt.Errorf("%q contains wildcard characters that cannot be used in a namespace name: %q", segment, r)
			}
		}
	}

	return nil
}

const (
	RootNamespaceID   = "root"
	RootNamespaceUUID = "00000000-0000-0000-0000-000000000000"
)

var (
	contextNamespace contextKeyNamespace = struct{}{}
	contextHeader    contextKeyHeader    = struct{}{}
	ErrNoNamespace   error               = errors.New("no namespace")
	RootNamespace    *Namespace          = &Namespace{
		ID:             RootNamespaceID,
		UUID:           RootNamespaceUUID,
		Path:           "",
		Tainted:        false,
		Locked:         false,
		CustomMetadata: make(map[string]string),
	}
)

// HasParent returns true if possibleParent is a parent namespace of n.
// Otherwise it returns false.
func (n *Namespace) HasParent(possibleParent *Namespace) bool {
	switch {
	case possibleParent.Path == "":
		return true
	case n.Path == "":
		return false
	default:
		return strings.HasPrefix(n.Path, possibleParent.Path)
	}
}

// ParentPath returns the path of the parent namespace. n.Path must be a
// canonicalized path.
func (n *Namespace) ParentPath() (string, bool) {
	return ParentOf(n.Path)
}

// ParentOf returns the path of the parent namespace. path must be a
// canonicalized path.
func ParentOf(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	segments := strings.SplitAfter(path, "/")
	if len(segments) <= 2 {
		return "", true
	}
	return strings.Join(segments[:len(segments)-2], ""), true
}

// TrimmedPath trims n.Path from the given path
func (n *Namespace) TrimmedPath(path string) string {
	return strings.TrimPrefix(path, n.Path)
}

func (n *Namespace) Clone(withUnlock bool) *Namespace {
	meta := make(map[string]string, len(n.CustomMetadata))
	maps.Copy(meta, n.CustomMetadata)

	data := &Namespace{
		ID:             n.ID,
		UUID:           n.UUID,
		Path:           n.Path,
		Tainted:        n.Tainted,
		Locked:         n.Locked,
		CustomMetadata: meta,
	}

	if withUnlock {
		data.UnlockKey = n.UnlockKey
	}

	return data
}

// GenerateUUID creates a UUID with a suffix representing the accessor of
// this namespace, when not the root namespace. This is of the form:
//
//	<uuid>.<accessor>
//
// Namespaced UUIDs can be useful for cross-namespace lookup operations and
// easy identification of which namespace a particular UUID belongs to. This
// can be validated by ValidateUUID(...) against a particular namespace.
func (n *Namespace) GenerateUUID() (string, error) {
	u, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}

	if n.ID != RootNamespaceID {
		u = fmt.Sprintf("%v.%v", u, n.ID)
	}

	return u, nil
}

// ValidateUUID takes a candidate identifier and ensures that this identifier
// matches this particular namespace. See ns.GenerateUUID(...) for expected
// format.
func (n *Namespace) ValidateUUID(candidate string) error {
	u, id := SplitIDFromString(candidate)
	_, err := uuid.ParseUUID(u)
	if err != nil {
		return fmt.Errorf("invalid uuid: %w", err)
	}

	if id != n.ID && (id != "" || n.ID != RootNamespaceID) {
		return errors.New("identifier has suffix of different namespace than expected")
	}

	return nil
}

// ContextWithNamespace adds the given namespace to the given context
func ContextWithNamespace(ctx context.Context, ns *Namespace) context.Context {
	return context.WithValue(ctx, contextNamespace, ns)
}

// RootContext adds the root namespace to the given context or returns a new
// context if the given context is nil
func RootContext(ctx context.Context) context.Context {
	if ctx == nil {
		return ContextWithNamespace(context.Background(), RootNamespace)
	}
	return ContextWithNamespace(ctx, RootNamespace)
}

// FromContext retrieves the namespace from a context, or an error
// if there is no namespace in the context.
func FromContext(ctx context.Context) (*Namespace, error) {
	if ctx == nil {
		return nil, errors.New("context was nil")
	}

	nsRaw := ctx.Value(contextNamespace)
	if nsRaw == nil {
		return nil, ErrNoNamespace
	}

	ns := nsRaw.(*Namespace)
	if ns == nil {
		return nil, ErrNoNamespace
	}

	return ns, nil
}

// ContextWithNamespaceHeader adds the given namespace header to the given context.
func ContextWithNamespaceHeader(ctx context.Context, nsHeader string) context.Context {
	return context.WithValue(ctx, contextHeader, Canonicalize(nsHeader))
}

// HeaderFromContext retrieves the namespace header from a context.
func HeaderFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	raw := ctx.Value(contextHeader)
	if raw == nil {
		return ""
	}

	return raw.(string)
}

// Canonicalize trims any prefix '/' and adds a trailing '/' to the
// provided string. The canonical root namespace path is the empty string.
func Canonicalize(nsPath string) string {
	// Canonicalize the path to not have a '/' prefix
	nsPath = strings.TrimPrefix(nsPath, "/")

	// Remove duplicate slashes and any ../ values if present.
	nsPath = path.Clean(nsPath)

	if nsPath == "." || nsPath == "root" {
		return ""
	}

	// Canonicalize the path to always having a '/' suffix
	if !strings.HasSuffix(nsPath, "/") {
		nsPath += "/"
	}

	return nsPath
}

func SplitIDFromString(input string) (string, string) {
	prefix := ""
	slashIdx := strings.LastIndex(input, "/")

	switch {
	case strings.HasPrefix(input, consts.LegacyBatchTokenPrefix):
		prefix = consts.LegacyBatchTokenPrefix
		input = input[2:]

	case strings.HasPrefix(input, consts.LegacyServiceTokenPrefix):
		prefix = consts.LegacyServiceTokenPrefix
		input = input[2:]
	case strings.HasPrefix(input, consts.BatchTokenPrefix):
		prefix = consts.BatchTokenPrefix
		input = input[4:]
	case strings.HasPrefix(input, consts.ServiceTokenPrefix):
		prefix = consts.ServiceTokenPrefix
		input = input[4:]

	case slashIdx > 0:
		// Leases will never have a b./s. to start
		if slashIdx == len(input)-1 {
			return input, ""
		}
		prefix = input[:slashIdx+1]
		input = input[slashIdx+1:]
	}

	idx := strings.LastIndex(input, ".")
	if idx == -1 {
		return prefix + input, ""
	}
	if idx == len(input)-1 {
		return prefix + input, ""
	}

	return prefix + input[:idx], input[idx+1:]
}

// MountPathDetails contains the details of a mount's location,
// consisting of the namespace of the mount and the path of the
// mount within the namespace
type MountPathDetails struct {
	Namespace *Namespace
	MountPath string
}

func (mpd *MountPathDetails) GetRelativePath(currNs *Namespace) string {
	subNsPath := strings.TrimPrefix(mpd.Namespace.Path, currNs.Path)
	return subNsPath + mpd.MountPath
}

func (mpd *MountPathDetails) GetFullPath() string {
	return mpd.Namespace.Path + mpd.MountPath
}
