// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
)

// IndexValue is the encoded value of the X-Vault-Index header(s) as sent by
// OpenBao.
type IndexValue struct {
	Cluster string `json:"cluster,omitempty"`
	Value   string `json:"value,omitempty"`
}

// Encode transforms this IndexValue to wire format.
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

// DecodeIndexValue takes the value of an X-Vault-Index header from OpenBao
// and parses it. It will not work with Vault Enterprise X-Vault-Index header
// values.
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
func (c *Client) SetInconsistent(behaviors ...string) {
	c.modifyLock.Lock()
	defer c.modifyLock.Unlock()

	c.setInconsistent(behaviors)
}

func (c *Client) setInconsistent(behaviors []string) {
	c.inconsistent = behaviors
}

func (c *Client) setStorageIndexTracker(mgr *simpleStorageIndexTracker) {
	c.indexTracker = mgr
}

func (c *Client) setIndexFromResult(request *Request, response *Response) error {
	index := response.Header.Get(IndexHeaderName)
	if index == "" {
		return nil
	}

	c.modifyLock.RLock()
	tracker := c.indexTracker
	c.modifyLock.RUnlock()

	if tracker == nil {
		return nil
	}

	tracker.set(index)
	return nil
}

// simpleStorageIndexTracker is an implementation of what will likely
// eventually become an exported interface for handling index assignments
// from responses and to requests.
type simpleStorageIndexTracker struct {
	lock   sync.RWMutex
	latest string
}

func newSimpleStorageIndexTracker() *simpleStorageIndexTracker {
	return &simpleStorageIndexTracker{}
}

func (i *simpleStorageIndexTracker) get() string {
	i.lock.RLock()
	defer i.lock.RUnlock()

	return i.latest
}

func (i *simpleStorageIndexTracker) set(index string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.latest = index
}
