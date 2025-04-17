package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
)

// namespaceTree represents a tree structure for efficient namespace path lookups.
// IMPORTANT: This structure is NOT thread-safe on its own and must be protected
// by the NamespaceStore's lock when being accessed or modified.
type namespaceTree struct {
	root *namespaceNode
	size int
}

type namespaceNode struct {
	parent   *namespaceNode
	children map[string]*namespaceNode
	entry    *namespace.Namespace
}

// newNamespaceTree creates a new namespaceTree with the given Namespace as
// root namespace
func newNamespaceTree(root *namespace.Namespace) *namespaceTree {
	node := &namespaceNode{
		entry:    root,
		children: make(map[string]*namespaceNode),
	}
	return &namespaceTree{
		root: node,
	}
}

// Get returns the namespace at a given path
func (nt *namespaceTree) Get(path string) *namespace.Namespace {
	path = namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(path, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil
		}

		node = n
	}

	return node.entry
}

// LongestPrefix finds the longest prefix of path that leads to a namespace. It
// returns the path to the namespace, the namespace and the remaining part of
// the input path.
func (nt *namespaceTree) LongestPrefix(path string) (string, *namespace.Namespace, string) {
	cpath := namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(cpath, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	for i := range segments {
		n, ok := node.children[segments[i]]
		if !ok {
			break
		}

		node = n
	}

	namespacePrefix := node.entry.Path
	pathSuffix := strings.TrimPrefix(path, namespacePrefix)
	return namespacePrefix, node.entry, pathSuffix
}

// List lists child Namespace entries at a given path, optionally including the
// namespace at the given path, optionally recursing down into all child
// namespaces.
func (nt *namespaceTree) List(path string, includeParent bool, recursive bool) ([]*namespace.Namespace, error) {
	path = namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(path, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	for i, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil, fmt.Errorf("unknown path: %s", namespace.Canonicalize(strings.Join(segments[:i], "/")))
		}

		node = n
	}

	var nodes []*namespaceNode
	nodes = append(nodes, node)

	var entries []*namespace.Namespace
	if includeParent {
		entries = make([]*namespace.Namespace, 0, len(node.children)+1)
		entries = append(entries, node.entry)
	}
	for idx := 0; idx < len(nodes); idx++ {
		node = nodes[idx]
		for _, child := range node.children {
			entries = append(entries, child.entry.Clone())
			if recursive {
				nodes = append(nodes, child)
			}
		}
	}

	return entries, nil
}

// Insert adds or updates the namespace with the given entry. It refuses to add
// the namespace if the parent namespace does not exist in the tree.
func (nt *namespaceTree) Insert(entry *namespace.Namespace) error {
	path := namespace.Canonicalize(entry.Path)
	if path == "" {
		return errors.New("can't insert root namespace")
	}
	segments := strings.SplitAfter(path, "/")
	segments = segments[:len(segments)-1]
	l := len(segments)
	node := nt.root
	for i, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			if i != l-1 {
				return errors.New("can't insert namespace with missing parent")
			}
			node.children[segment] = &namespaceNode{
				parent:   node,
				children: make(map[string]*namespaceNode),
				entry:    entry,
			}
			nt.size += 1
			return nil
		}

		node = n
	}

	node.entry = entry

	return nil
}

// Delete removes a namespace from the tree using the path. The delete is not
// cascading and refuses to remove namespaces with existing children.
func (nt *namespaceTree) Delete(path string) error {
	path = namespace.Canonicalize(path)
	if path == "" {
		return errors.New("can't delete root namespace")
	}
	segments := strings.SplitAfter(path, "/")
	segments = segments[:len(segments)-1]
	node := nt.root
	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil
		}

		node = n
	}

	if len(node.children) > 0 {
		return errors.New("can't delete namespace with children")
	}

	delete(node.parent.children, segments[len(segments)-1])
	nt.size -= 1

	return nil
}

// validate validates that all nodes in the tree have entry set
func (nt *namespaceTree) validate() error {
	nodes := make([]*namespaceNode, 0, nt.size)
	nodes = append(nodes, nt.root)

	var errs []error

	for idx := 0; idx < len(nodes); idx++ {
		node := nodes[idx]
		for _, child := range node.children {
			if node.entry == nil {
				errs = append(errs, fmt.Errorf("orphan namespace found: %s", child.entry.Path))
			}
			nodes = append(nodes, child)
		}
	}

	return errors.Join(errs...)
}

// unsafeInsert performs an unsafe insert of the namespace entry. It will create
// any intermediate tree entries as necessary and will not perform validation of
// the tree. You MUST call validate yourself when done inserting.
func (nt *namespaceTree) unsafeInsert(entry *namespace.Namespace) {
	segments := strings.SplitAfter(entry.Path, "/")
	segments = segments[:len(segments)-1]
	node := nt.root

	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			child := &namespaceNode{
				parent:   node,
				children: make(map[string]*namespaceNode),
			}
			node.children[segment] = child
			nt.size += 1
			node = child
			continue
		}

		node = n
	}
	node.entry = entry
}
