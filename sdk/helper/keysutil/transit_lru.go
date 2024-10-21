// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keysutil

import lru "github.com/hashicorp/golang-lru/v2"

type TransitLRU struct {
	size int
	lru  *lru.TwoQueueCache[string, interface{}]
}

func NewTransitLRU(size int) (*TransitLRU, error) {
	lru, err := lru.New2Q[string, interface{}](size)
	return &TransitLRU{lru: lru, size: size}, err
}

func (c *TransitLRU) Delete(key interface{}) {
	c.lru.Remove(key.(string))
}

func (c *TransitLRU) Load(key interface{}) (value interface{}, ok bool) {
	return c.lru.Get(key.(string))
}

func (c *TransitLRU) Store(key, value interface{}) {
	c.lru.Add(key.(string), value)
}

func (c *TransitLRU) Size() int {
	return c.size
}
