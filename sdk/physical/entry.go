// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package physical

import (
	"encoding/hex"
	"fmt"
)

// Entry is used to represent data stored by the physical backend
type Entry struct {
	Key      string
	Value    []byte
	SealWrap bool `json:"seal_wrap,omitempty"`

	// Only used in replication
	ValueHash []byte
}

func (e *Entry) String() string {
	return fmt.Sprintf("Key: %s. SealWrap: %t. Value: %s. ValueHash: %s", e.Key, e.SealWrap, hex.EncodeToString(e.Value), hex.EncodeToString(e.ValueHash))
}

// Performs a deep clone of this entry.
func (e *Entry) Clone() *Entry {
	if e == nil {
		return nil
	}

	result := &Entry{
		Key:      e.Key,
		SealWrap: e.SealWrap,
	}

	if e.Value != nil {
		result.Value = make([]byte, len(e.Value))
		copy(result.Value, e.Value)
	}

	if e.ValueHash != nil {
		result.ValueHash = make([]byte, len(e.ValueHash))
		copy(result.ValueHash, e.Value)
	}

	return result
}
