// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package namespace

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Tree represents a tree structure for efficient namespace lookups by path.
// IMPORTANT: This structure is NOT thread-safe on its own and must be protected
// by the NamespaceStore's lock when being accessed or modified.
type Tree struct {
	root *treeNode
	size int

	CreateHook func(*Namespace) error
	DeleteHook func(*Namespace) error
}

type treeNode struct {
	children map[string]*treeNode
	entry    *Namespace
}

// NewTree creates a new Tree with the given Namespace as root namespace.
func NewTree(root *Namespace) *Tree {
	node := &treeNode{
		entry:    root,
		children: make(map[string]*treeNode),
	}
	return &Tree{
		root: node,
		size: 1,
	}
}

func (t *Tree) nodeAt(path string) *treeNode {
	path = Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(path, "/")
		segments = segments[:len(segments)-1]
	}
	node := t.root
	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil
		}
		node = n
	}
	return node
}

// Get returns the namespace at a given path.
func (t *Tree) Get(path string) *Namespace {
	node := t.nodeAt(path)
	if node == nil {
		return nil
	}
	return node.entry
}

// IsLeaf returns true if the given path represents a leaf node, i.e., a
// namespace with no children.
func (t *Tree) IsLeaf(path string) bool {
	node := t.nodeAt(path)
	if node == nil {
		return false
	}
	return len(node.children) == 0
}

// LongestPrefix finds the longest prefix of path that leads to a namespace. It
// returns the path to the namespace, the namespace and the remaining part of
// the input path.
func (t *Tree) LongestPrefix(path string) (string, *Namespace, string) {
	cpath := Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(cpath, "/")
		segments = segments[:len(segments)-1]
	}
	node := t.root
	for i := range segments {
		n, ok := node.children[segments[i]]
		if !ok {
			break
		}
		node = n
	}
	namespacePrefix := node.entry.Path
	pathSuffix := strings.TrimPrefix(path, namespacePrefix)
	return namespacePrefix, node.entry.Clone(false), pathSuffix
}

func (t *Tree) PostOrderTraversal(path string, op func(namespace *Namespace)) {
	node := t.nodeAt(path)
	if node == nil {
		return
	}

	nodes := []*treeNode{node}
	ordNodes := []*treeNode{}

	for len(nodes) > 0 {
		node := nodes[len(nodes)-1]
		nodes = nodes[:len(nodes)-1]
		ordNodes = append(ordNodes, node)

		for _, childNode := range node.children {
			nodes = append(nodes, childNode)
		}
	}

	for _, ordNode := range slices.Backward(ordNodes) {
		op(ordNode.entry)
	}
}

// WalkPath calls predicate by walking towards the given namespace, starting
// from the root, until the predicate returns true or the namespace was reached
// or not found.
func (t *Tree) WalkPath(path string, predicate func(namespace *Namespace) bool) {
	path = Canonicalize(path)
	var segments []string
	if path != "" {
		segments = strings.SplitAfter(path, "/")
		segments = segments[:len(segments)-1]
	}

	// intentionally not calling the predicate on the root
	node := t.root
	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok || predicate(n.entry) {
			return
		}

		node = n
	}
}

// Walk walks the tree starting at path and calls callback on each encountered
// child namespace. An error is returned if the initial path does not exist.
func (t *Tree) Walk(path string, recursive bool, callback func(*Namespace)) error {
	node := t.nodeAt(path)
	if node == nil {
		return fmt.Errorf("unknown path: %s", Canonicalize(path))
	}

	queue := make([]*treeNode, 0, len(node.children))
	for _, child := range node.children {
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		node, queue = queue[0], queue[1:]
		callback(node.entry)
		if recursive {
			for _, child := range node.children {
				queue = append(queue, child)
			}
		}
	}

	return nil
}

// Insert adds or updates the namespace with the given entry. It refuses to add
// the namespace if the parent namespace does not exist in the tree.
func (t *Tree) Insert(entry *Namespace) error {
	path := Canonicalize(entry.Path)
	if path == "" {
		return errors.New("can't insert root namespace")
	}
	segments := strings.SplitAfter(path, "/")
	segments = segments[:len(segments)-1]
	l := len(segments)
	node := t.root
	for i, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			if i != l-1 {
				return errors.New("can't insert namespace with missing parent")
			}

			if t.CreateHook != nil {
				// Call CreateHook before mutating the tree below so we don't
				// need code to undo the mutation on hook failure.
				if err := t.CreateHook(entry); err != nil {
					return err
				}
			}

			node.children[segment] = &treeNode{
				children: make(map[string]*treeNode),
				entry:    entry,
			}
			t.size += 1
			return nil
		}

		node = n
	}

	node.entry = entry

	return nil
}

// Delete removes a namespace from the tree using the path. The delete is not
// cascading and refuses to remove namespaces with existing children.
func (t *Tree) Delete(path string) error {
	path = Canonicalize(path)
	if path == "" {
		return errors.New("can't delete root namespace")
	}

	segments := strings.SplitAfter(path, "/")
	segments = segments[:len(segments)-1]

	node := t.root
	var parent *treeNode

	for _, segment := range segments {
		n, ok := node.children[segment]
		if !ok {
			return nil
		}

		node, parent = n, node
	}

	if len(node.children) > 0 {
		return errors.New("can't delete namespace with children")
	}

	delete(parent.children, segments[len(segments)-1])
	t.size -= 1

	if t.DeleteHook != nil {
		if err := t.DeleteHook(node.entry); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates that all nodes in the tree have entry set.
func (t *Tree) Validate() error {
	nodes := make([]*treeNode, 0, t.size)
	nodes = append(nodes, t.root)

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
