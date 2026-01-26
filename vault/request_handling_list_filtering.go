// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/helper/identity"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (c *Core) filterListResponse(ctx context.Context, req *logical.Request, unauth bool, auth *logical.Auth, acl *ACL, te *logical.TokenEntry, entity *identity.Entity, resp *logical.Response) error {
	// Ignore non-list operations.
	switch req.Operation {
	case logical.ListOperation:
	case logical.ScanOperation:
	default:
		return nil
	}

	// No filtering, so nothing to do.
	if auth.ResponseKeysFilterPath == "" {
		return nil
	}

	// Secret and Auth should not be set on List operation responses which
	// expect to be filtered.
	if resp.Secret != nil {
		c.logger.Error("non-empty secret on filtered list response", "path", req.Path)
		return ErrInternalError
	}
	if resp.Auth != nil {
		c.logger.Error("non-empty auth on filtered list response", "path", req.Path)
		return ErrInternalError
	}

	// Exit early when there is no data.
	if resp.Data == nil {
		return nil
	}

	// Validate we have all required data fields and no unexpected ones.
	keysRaw, present := resp.Data["keys"]
	keyInfoRaw, keyInfoPresent := resp.Data["key_info"]
	if !present {
		c.logger.Error("missing required parameter keys on filtered list response", "path", req.Path)
		return ErrInternalError
	}
	for keyName := range resp.Data {
		if keyName == "keys" || keyName == "key_info" {
			continue
		}

		c.logger.Error("unknown parameter on filtered list response", "path", req.Path, "field", keyName)
		return ErrInternalError
	}
	keys, ok := keysRaw.([]string)
	if !ok {
		c.logger.Error("invalid type for parameter keys on filtered list response", "path", req.Path, "type", fmt.Sprintf("%T", keysRaw))
		return ErrInternalError
	}
	var keyInfo map[string]interface{}
	if keyInfoPresent {
		keyInfo, ok = keyInfoRaw.(map[string]interface{})
		if !ok {
			c.logger.Error("invalid type for parameter key_info on filtered list response", "path", req.Path, "type", fmt.Sprintf("%T", keysRaw))
			return ErrInternalError
		}
	}

	filteredKeys := make([]string, 0, len(keys))
	tmpl, err := compileTemplatePathForFiltering(auth.ResponseKeysFilterPath)
	if err != nil {
		c.logger.Error("failed to compile template on filtered list response", "path", req.Path, "err", err)
		return ErrInternalError
	}

	for _, key := range keys {
		checkPath, err := useTemplateForFiltering(tmpl, req.Path, key)
		if err != nil {
			c.logger.Error("failed to use template on filtered list response", "path", req.Path, "err", err)
			return ErrInternalError
		}

		c.logger.Debug("got templated path", "path", req.Path, "key", key, "checkPath", checkPath)

		op := logical.ReadOperation
		if strings.HasSuffix(key, "/") {
			op = logical.ListOperation
		}

		// n.b., no required parameter or wrap handling is currently supported.
		checkReq := &logical.Request{
			Operation: op,
			Path:      checkPath,
			Headers:   req.Headers,
			Data:      map[string]interface{}{},
		}

		rootPath := c.router.RootPath(ctx, checkPath)
		if rootPath && unauth {
			// Per note in c.CheckToken(...), we cannot access root path in
			// unauthenticated request, even if authentication data is
			// attached to the login request. This is because login requests
			// cannot be root paths.
			continue
		}

		authResults := c.performPolicyChecks(ctx, acl, te, checkReq, entity, &PolicyCheckOpts{
			Unauth:            unauth,
			RootPrivsRequired: rootPath,
		})

		if authResults.Allowed {
			c.logger.Debug("allowed path", "checkPath", checkPath, "key", key)
			filteredKeys = append(filteredKeys, key)
		}
	}

	resp.Data["keys"] = filteredKeys

	if keyInfoPresent {
		filteredInfo := make(map[string]interface{}, len(filteredKeys))
		for _, key := range filteredKeys {
			if data, present := keyInfo[key]; present {
				filteredInfo[key] = data
			}
		}
		resp.Data["key_info"] = filteredInfo
	}

	return nil
}

func compileTemplatePathForFiltering(tmpl string) (template.StringTemplate, error) {
	return template.NewTemplate(template.Template(tmpl))
}

func useTemplateForFiltering(t template.StringTemplate, path string, key string) (string, error) {
	return t.Generate(map[string]interface{}{
		"key":  key,
		"path": path,
	})
}
