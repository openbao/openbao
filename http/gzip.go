// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/openbao/openbao/vault"
)

type uiAsset struct {
	raw []byte
	gz  []byte
	typ string
}

var (
	uiAssets     = map[string]uiAsset{}
	uiAssetsOnce sync.Once
)

// compressibleTypes defines MIME types that should be compressed
var compressibleTypes = map[string]struct{}{
	"text/html":              {},
	"text/css":               {},
	"text/plain":             {},
	"text/xml":               {},
	"application/javascript": {},
	"application/json":       {},
	"application/xml":        {},
	"application/xhtml+xml":  {},
	"image/svg+xml":          {},
}

// isCompressible checks if the MIME type should be compressed
func isCompressible(mimeType string) bool {
	// Remove charset and other parameters from MIME type
	if idx := strings.Index(mimeType, ";"); idx != -1 {
		mimeType = mimeType[:idx]
	}
	mimeType = strings.TrimSpace(mimeType)
	_, ok := compressibleTypes[mimeType]
	return ok
}

func loadUIAsset(core *vault.Core, fs http.FileSystem, name string) (uiAsset, error) {
	f, err := fs.Open(name)
	if err != nil {
		return uiAsset{}, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			core.Logger().Error("failed to close UI asset file", "file", name, "error", cerr)
		}
	}()

	raw, err := io.ReadAll(f)
	if err != nil {
		return uiAsset{}, err
	}

	mimeType := mime.TypeByExtension(filepath.Ext(name))
	asset := uiAsset{
		typ: mimeType,
	}

	// Compress only for supported MIME types
	if isCompressible(mimeType) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err = gz.Write(raw); err != nil {
			return uiAsset{}, err
		}
		if err = gz.Close(); err != nil {
			return uiAsset{}, err
		}
		asset.gz = buf.Bytes()
	} else {
		asset.raw = raw
	}

	return asset, nil
}

// walkUIFiles recursively walks through the file system and collects all file paths
func walkUIFiles(core *vault.Core, filesystem http.FileSystem, path string) ([]string, error) {
	var files []string

	f, err := filesystem.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			core.Logger().Error("failed to close UI asset file", "file", path, "error", cerr)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{path}, nil
	}

	entries, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			subFiles, err := walkUIFiles(core, filesystem, entryPath)
			if err != nil {
				return nil, err
			}
			files = append(files, subFiles...)
		} else {
			files = append(files, entryPath)
		}
	}

	return files, nil
}

func ensureUIAssets(core *vault.Core, fs http.FileSystem) error {
	var onceErr error
	uiAssetsOnce.Do(func() {
		uiFiles, err := walkUIFiles(core, fs, "/")
		if err != nil {
			onceErr = err
			return
		}

		tmp := make(map[string]uiAsset, len(uiFiles))
		for _, name := range uiFiles {
			asset, err := loadUIAsset(core, fs, name)
			if err != nil {
				onceErr = err
				return
			}
			cleanName := strings.TrimPrefix(name, "/")
			tmp[cleanName] = asset
		}
		uiAssets = tmp
	})
	return onceErr
}

func serveUIAsset(core *vault.Core, w http.ResponseWriter, r *http.Request, name string) {
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		name = "index.html"
	}
	asset, ok := uiAssets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", asset.typ)

	if len(asset.gz) > 0 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		if _, err := w.Write(asset.gz); err != nil {
			core.Logger().Error("failed to write UI asset", "file", name, "error", err)
			return
		}
		return
	}

	if _, err := w.Write(asset.raw); err != nil {
		core.Logger().Error("failed to write UI asset", "file", name, "error", err)
	}
}
