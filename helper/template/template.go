package template

import "github.com/openbao/openbao/sdk/v2/helper/template"

func UseTemplateForFiltering(t template.StringTemplate, path string, key string) (string, error) {
	return t.Generate(map[string]interface{}{
		"key":  key,
		"path": path,
	})
}

func CompileTemplatePathForFiltering(tmpl string) (template.StringTemplate, error) {
	return template.NewTemplate(template.Template(tmpl))
}
