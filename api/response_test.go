// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResponseIsJSON(t *testing.T) {
	t.Run("standard_application_json_content_type", func(t *testing.T) {
		r := http.Response{Header: make(http.Header)}
		r.Header.Set("Content-Type", "application/json")
		resp := Response{&r}
		assert.True(t, resp.IsJSON())
	})
	t.Run("custom_application_json_content_type", func(t *testing.T) {
		r := http.Response{Header: make(http.Header)}
		r.Header.Set("Content-Type", "application/custom.api+json")
		resp := Response{&r}
		assert.True(t, resp.IsJSON())
	})
	t.Run("defaults_to_json_if_no_content_type", func(t *testing.T) {
		r := http.Response{Header: make(http.Header)}
		resp := Response{&r}
		assert.True(t, resp.IsJSON())
	})
	t.Run("text_plan_is_not_json", func(t *testing.T) {
		r := http.Response{Header: make(http.Header)}
		r.Header.Set("Content-Type", "text/plain")
		resp := Response{&r}
		assert.False(t, resp.IsJSON())
	})
}
