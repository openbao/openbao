// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package seal

import (
	"sync"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

type Envelope struct {
	envelope *wrapping.EnvelopeInfo
	once     sync.Once
}

func NewEnvelope() *Envelope {
	return &Envelope{}
}

func (e *Envelope) init() {
	e.envelope = new(wrapping.EnvelopeInfo)
}

func (e *Envelope) Encrypt(plaintext, aad []byte) (*wrapping.EnvelopeInfo, error) {
	defer metrics.MeasureSince([]string{"seal", "envelope", "encrypt"}, time.Now())
	e.once.Do(e.init)

	return wrapping.EnvelopeEncrypt(plaintext, wrapping.WithAad(aad))
}

func (e *Envelope) Decrypt(data *wrapping.EnvelopeInfo, aad []byte) ([]byte, error) {
	defer metrics.MeasureSince([]string{"seal", "envelope", "decrypt"}, time.Now())
	e.once.Do(e.init)

	return wrapping.EnvelopeDecrypt(data, wrapping.WithAad(aad))
}
