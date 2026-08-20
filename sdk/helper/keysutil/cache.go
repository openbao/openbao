// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keysutil

type Cache interface {
	Delete(key any)
	Load(key any) (value any, ok bool)
	Store(key, value any)
	Size() int
}
