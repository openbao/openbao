package vault

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
)

type namespaceTree struct {
	root *namespaceNode
	size int
}

type namespaceNode struct {
	parent   *namespaceNode
	children map[string]*namespaceNode
	entry    *NamespaceEntry
}

func newNamespaceTree(root *NamespaceEntry) *namespaceTree {
	node := &namespaceNode{
		entry:    root,
		children: make(map[string]*namespaceNode),
	}
	return &namespaceTree{
		root: node,
	}
}

func (nt *namespaceTree) Get(path string) (*NamespaceEntry, bool) {
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
			return nil, false
		}

		node = n
	}

	return node.entry, true
}

func (nt *namespaceTree) LongestPrefix(path string) (string, *NamespaceEntry, string) {
	cpath := namespace.Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(cpath, "/")
		segments = segments[:len(segments)-1]
	}
	node := nt.root
	var i int
	for i = range segments {
		n, ok := node.children[segments[i]]
		if !ok {
			break
		}

		node = n
	}

	namespacePrefix := node.entry.Namespace.Path
	pathSuffix := strings.TrimPrefix(path, namespacePrefix)
	return namespacePrefix, node.entry, pathSuffix
}

func (nt *namespaceTree) List(path string, includeParent bool, recursive bool) ([]*NamespaceEntry, error) {
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

	var entries []*NamespaceEntry
	if includeParent {
		entries = append(entries, node.entry)
	}
	var idx int
	for {
		if idx >= len(nodes) {
			break
		}
		node = nodes[idx]
		for _, child := range node.children {
			entries = append(entries, child.entry.Clone())
			if recursive {
				nodes = append(nodes, child)
			}
		}
		idx += 1
	}

	return entries, nil
}

func (nt *namespaceTree) Insert(entry *NamespaceEntry) error {
	path := namespace.Canonicalize(entry.Namespace.Path)
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

func (nt *namespaceTree) validate() error {
	nodes := make([]*namespaceNode, 0, nt.size)
	nodes = append(nodes, nt.root)

	var errs []error

	for idx := range nt.size {
		node := nodes[idx]
		for _, child := range node.children {
			if node.entry == nil {
				errs = append(errs, fmt.Errorf("orphan namespace found: %s", child.entry.Namespace.Path))
			}
			nodes = append(nodes, child)
		}
	}

	return errors.Join(errs...)
}

func (nt *namespaceTree) load(entries []*NamespaceEntry) error {
	for _, entry := range entries {
		path := strings.Split(entry.Namespace.Path[:len(entry.Namespace.Path)-1], "/")
		node := nt.root

		for _, segment := range path {
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

	return nt.validate()
}
