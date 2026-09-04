// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
)

type IndexValue struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

func (i *IndexValue) Encode() (string, error) {
	if i == nil {
		return "", nil
	}

	value, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("failed to marshal: %w", err)
	}

	return base64.StdEncoding.EncodeToString(value), nil
}

func DecodeIndexValue(value string) (*IndexValue, error) {
	if value == "" {
		return nil, nil
	}

	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %w", err)
	}

	var i IndexValue
	if err := json.Unmarshal(data, &i); err != nil {
		return nil, err
	}

	return &i, nil
}

// SetInconsistent provides one or more values for the X-Vault-Inconsistent
// header. See notes around Index* constants in client.go.
func (c *Client) SetInconsistent(behaviors []string) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.setInconsistent(behaviors)
}

func (c *Client) setInconsistent(behaviors []string) {
	c.inconsistent = behaviors
}

// FailInconsistent sets X-Vault-Inconsistent to fail, ensuring a 429-based
// backoff-retry logic for stale index headers.
func (c *Client) FailInconsistent() {
	c.SetInconsistent([]string{IndexInconsistentFail})
}

// ForwardInconsistent sets X-Vault-Inconsistent to forward-active-node,
// ensuring stale index header values are forwarded instead.
func (c *Client) ForwardInconsistent() {
	c.SetInconsistent([]string{IndexInconsistentForward})
}

// AwaitInconsistent sets the X-Vault-Inconsistent to await-state, specifying
// an explicit fallback behavior if waiting is not sufficient.
func (c *Client) AwaitInconsistent(fallback string) {
	if fallback == "" {
		c.DefaultAwaitInconsistent()
		return
	}

	c.SetInconsistent([]string{IndexInconsistentAwait, fallback})
}

// AwaitInconsistent sets the X-Vault-Inconsistent to await-state, relying
// on the server's default behavior if waiting is not sufficient.
func (c *Client) DefaultAwaitInconsistent() {
	c.SetInconsistent([]string{IndexInconsistentAwait})
}

// SetIndexManager specifies index management behavior for this client. See
// interface definition of IndexManager for more information.
func (c *Client) SetIndexManager(mgr IndexManager) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.setIndexManager(mgr)
}

func (c *Client) setIndexManager(mgr IndexManager) {
	c.state = mgr
}

func (c *Client) setIndexFromResult(request *Request, response *Response) error {
	addr := request.URL.String()
	index := response.Header.Get(IndexHeaderName)
	if index == "" {
		return nil
	}

	c.modifyLock.RLock()
	state := c.state
	c.modifyLock.RUnlock()

	if state == nil {
		return nil
	}

	return state.Set(addr, index)
}

// WithIndexManager creates a new cloned client with a unique index manager;
// other operations including Clone preserve the shared index manager
// instance.
func (c *Client) WithIndexManager(mgr IndexManager) *Client {
	c2 := *c //nolint:copylocks
	c2.modifyLock = sync.RWMutex{}
	c2.state = mgr
	return &c2
}

// IndexManager specifies the behavior of index resolution. Get is called
// when building each request and Set is called after receiving an answer,
// if it has an index header value. Each implementation of IndexManager is
// free to use or discard contextual information as appropriate.
type IndexManager interface {
	// Get the current index for the specified address and namespace.
	Get(addr string, namespace string) string

	// Set stores the new index for the specified address and namespace.
	Set(addr string, index string) error
}

type simpleIndexManager struct {
	lock   sync.RWMutex
	latest string
}

var _ IndexManager = &simpleIndexManager{}

// NewSimpleIndexManager creates a simple index manager instance that stores
// only the latest (by order of Set(...) call) index. This may break down in
// highly parallel applications, but should generally be sufficiently correct
// except with many interleaved read/write calls.
//
// It does not handle cluster addresses or namespaces.
func NewSimpleIndexManager() IndexManager {
	return &simpleIndexManager{}
}

func (i *simpleIndexManager) Get(_ string, _ string) string {
	i.lock.RLock()
	defer i.lock.RUnlock()

	return i.latest
}

func (i *simpleIndexManager) Set(_ string, index string) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.latest = index
	return nil
}
