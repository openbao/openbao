// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package template

import "github.com/openbao/openbao/sdk/v2/helper/template"

func UseTemplateForFiltering(t template.StringTemplate, path string, key string) (string, error) {
	return t.Generate(map[string]any{
		"key":  key,
		"path": path,
	})
}

func CompileTemplatePathForFiltering(tmpl string) (template.StringTemplate, error) {
	return template.NewTemplate(template.Template(tmpl))
}
