// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package oci

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
)

// Plugin download error behavior constants
const (
	PluginDownloadFailStartup = "fail"
	PluginDownloadContinue    = "continue"
	PluginCacheDir            = ".oci-cache"
)

// PluginConfig represents the configuration for a single plugin
type PluginConfig struct {
	URL        string `hcl:"url"`
	BinaryName string `hcl:"binary_name"`
	SHA256Sum  string `hcl:"sha256sum"`
}

// PluginOCIAuthConfig represents OCI registry authentication configuration
type PluginOCIAuthConfig struct {
	Username string `hcl:"username"`
	Password string `hcl:"password"`
	Token    string `hcl:"token"`
}

// PluginConfigProvider provides plugin configuration data
type PluginConfigProvider interface {
	GetPlugins() map[string]*PluginConfig
	GetPluginDownloadBehavior() string
	GetPluginOCIAuth() map[string]*PluginOCIAuthConfig
}

// PluginDownloader handles downloading and managing OCI-based plugins
type PluginDownloader struct {
	pluginDirectory string
	config          PluginConfigProvider
	logger          hclog.Logger
}

// NewPluginDownloader creates a new OCI plugin downloader
func NewPluginDownloader(pluginDirectory string, config PluginConfigProvider, logger hclog.Logger) *PluginDownloader {
	return &PluginDownloader{
		pluginDirectory: pluginDirectory,
		config:          config,
		logger:          logger,
	}
}

// ReconcilePlugins downloads and validates all configured OCI plugins
func (d *PluginDownloader) ReconcilePlugins(ctx context.Context) error {
	plugins := d.config.GetPlugins()
	if len(plugins) == 0 {
		d.logger.Debug("no plugin configuration found")
		return nil
	}

	for pluginName, pluginConfig := range plugins {
		if pluginConfig == nil {
			continue
		}

		pluginLogger := d.logger.With("plugin", pluginName)
		pluginLogger.Debug("processing plugin", "url", pluginConfig.URL, "binary_name", pluginConfig.BinaryName)

		// Fast path: check if plugin already exists and matches expected SHA256
		if d.IsPluginCacheValid(pluginName, pluginConfig) {
			pluginLogger.Info("plugin is cached on disk, skipping download")
			continue
		}

		// Slow path: download from OCI registry
		if err := d.DownloadPlugin(ctx, pluginName, pluginConfig, pluginLogger); err != nil {
			if d.shouldFailOnPluginError() {
				return fmt.Errorf("failed to download plugin %q: %w", pluginName, err)
			} else {
				pluginLogger.Warn("failed to download plugin", "error", err)
				continue
			}
		}
	}

	return nil
}

// shouldFailOnPluginError determines whether plugin download errors should fail startup
func (d *PluginDownloader) shouldFailOnPluginError() bool {
	behavior := d.config.GetPluginDownloadBehavior()
	if behavior == "" {
		behavior = PluginDownloadFailStartup
	}

	return behavior == PluginDownloadFailStartup
}

// IsPluginCacheValid checks if the plugin already exists in the plugin directory
// and matches the expected SHA256 hash (fast path)
func (d *PluginDownloader) IsPluginCacheValid(pluginName string, config *PluginConfig) bool {
	if d.pluginDirectory == "" {
		return false
	}

	// Check if the symlink exists in the plugin directory
	symlinkPath := filepath.Join(d.pluginDirectory, pluginName)

	// Check if symlink exists and is a symlink
	linkInfo, err := os.Lstat(symlinkPath)
	if err != nil {
		return false
	}

	if linkInfo.Mode()&os.ModeSymlink == 0 {
		// If it's not a symlink, it might be a regular file from manual installation
		// Let's validate it directly
		actualHash, err := d.calculateSHA256(symlinkPath)
		if err != nil {
			return false
		}
		return strings.EqualFold(actualHash, config.SHA256Sum)
	}

	// Follow the symlink to get the actual cached file
	cachedFilePath, err := os.Readlink(symlinkPath)
	if err != nil {
		return false
	}

	// Make sure it's an absolute path
	if !filepath.IsAbs(cachedFilePath) {
		cachedFilePath = filepath.Join(d.pluginDirectory, cachedFilePath)
	}

	// Check if the cached file exists
	if _, err := os.Stat(cachedFilePath); os.IsNotExist(err) {
		return false
	}

	// Validate SHA256 of the cached file
	actualHash, err := d.calculateSHA256(cachedFilePath)
	if err != nil {
		d.logger.Debug("failed to calculate plugin hash", "plugin", pluginName, "error", err)
		return false
	}

	return strings.EqualFold(actualHash, config.SHA256Sum)
}

// DownloadPlugin downloads a plugin from an OCI registry
func (d *PluginDownloader) DownloadPlugin(ctx context.Context, pluginName string, config *PluginConfig, logger hclog.Logger) error {
	logger.Info("downloading plugin from OCI registry",
		"url", config.URL)

	// Parse the OCI reference
	ref, err := name.ParseReference(config.URL)
	if err != nil {
		return fmt.Errorf("invalid OCI reference %q: %w", config.URL, err)
	}

	// Set up authentication
	authenticator, err := d.getOCIAuthenticator(ref.Context().RegistryStr(), logger)
	if err != nil {
		return fmt.Errorf("failed to set up OCI authentication: %w", err)
	}

	// Download the image
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuth(authenticator))
	if err != nil {
		return fmt.Errorf("failed to download OCI image: %w", err)
	}

	// Extract the plugin binary from the image using hidden cache path
	// Format: <plugin_directory>/.oci-cache/<plugin_name>/<sha256_prefix>/<binary_name>
	sha256Prefix := config.SHA256Sum[:8]
	cacheDir := filepath.Join(d.pluginDirectory, PluginCacheDir, pluginName, sha256Prefix)
	cachedPluginPath := filepath.Join(cacheDir, config.BinaryName)

	if err := d.ExtractPluginFromImage(img, cachedPluginPath, config.BinaryName, logger); err != nil {
		return fmt.Errorf("failed to extract plugin from OCI image: %w", err)
	}

	// Verify the SHA256 hash of the cached file
	actualHash, err := d.calculateSHA256(cachedPluginPath)
	if err != nil {
		// Clean up the cached file if hash verification fails
		removeErr := os.Remove(cachedPluginPath)
		if removeErr != nil {
			return errors.Join(fmt.Errorf("failed to calculate plugin hash: %w", err),
				fmt.Errorf("failed to remove cached file: %w", removeErr))
		}
		return fmt.Errorf("failed to calculate plugin hash: %w", err)
	}

	if !strings.EqualFold(actualHash, config.SHA256Sum) {
		// Clean up the cached file if hash doesn't match
		removeErr := os.Remove(cachedPluginPath)
		if removeErr != nil {
			return errors.Join(fmt.Errorf("plugin hash mismatch: expected %s, got %s", config.SHA256Sum, actualHash),
				fmt.Errorf("failed to remove cached file: %w", removeErr))
		}
		return fmt.Errorf("plugin hash mismatch: expected %s, got %s", config.SHA256Sum, actualHash)
	}

	// Create symlink in the plugin directory pointing to the cached file
	symlinkPath := filepath.Join(d.pluginDirectory, pluginName)

	// Remove existing symlink or file if it exists
	if _, err := os.Lstat(symlinkPath); err == nil {
		if err := os.Remove(symlinkPath); err != nil {
			logger.Warn("failed to remove existing plugin file/symlink", "path", symlinkPath, "error", err)
		}
	}

	// Create symlink (use relative path for portability)
	relativeTarget, err := filepath.Rel(d.pluginDirectory, cachedPluginPath)
	if err != nil {
		// Fallback to absolute path if relative path calculation fails
		relativeTarget = cachedPluginPath
	}

	if err := os.Symlink(relativeTarget, symlinkPath); err != nil {
		return fmt.Errorf("failed to create plugin symlink: %w", err)
	}

	logger.Info("successfully downloaded and validated plugin",
		"cached_path", cachedPluginPath,
		"symlink_path", symlinkPath,
		"hash", actualHash)

	return nil
}

// calculateSHA256 computes the SHA256 hash of a file
func (d *PluginDownloader) calculateSHA256(filePath string) (result string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		closeErr := file.Close()
		// in case closing the file returns an error
		// make calculateSHA256 exit with that error
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	hasher := sha256.New()
	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", err
	}

	result = hex.EncodeToString(hasher.Sum(nil))
	return result, err
}

// getOCIAuthenticator returns the appropriate authenticator for the given registry
func (d *PluginDownloader) getOCIAuthenticator(registry string, logger hclog.Logger) (authn.Authenticator, error) {
	// Check if we have authentication configured for this registry
	authConfigs := d.config.GetPluginOCIAuth()
	authConfig, exists := authConfigs[registry]
	if !exists {
		logger.Debug("no authentication configured for registry, using anonymous", "registry", registry)
		return authn.Anonymous, nil
	}

	// Use token-based auth if available
	if authConfig.Token != "" {
		logger.Debug("using token authentication for registry", "registry", registry)
		return &authn.Bearer{Token: authConfig.Token}, nil
	}

	// Use username/password auth if available
	if authConfig.Username != "" && authConfig.Password != "" {
		logger.Debug("using basic authentication for registry", "registry", registry)
		return &authn.Basic{
			Username: authConfig.Username,
			Password: authConfig.Password,
		}, nil
	}

	logger.Debug("no valid authentication method found, using anonymous", "registry", registry)
	return authn.Anonymous, nil
}

// ExtractPluginFromImage extracts the plugin binary from the OCI image (public for testing)
func (d *PluginDownloader) ExtractPluginFromImage(img v1.Image, targetPath string, binaryName string, logger hclog.Logger) (err error) {
	logger.Debug("extracting plugin from OCI image", "target", targetPath, "binary", binaryName)

	// Create the plugin directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	// Use mutate.Extract to get the final filesystem as a tar stream
	rc := mutate.Extract(img)
	defer func() {
		closeErr := rc.Close()
		// in case closing the reader returns an error
		// exit with that error
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	// Create a tar reader to read the extracted filesystem
	tarReader := tar.NewReader(rc)

	// Search for the binary in the root of the image
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar entry: %w", err)
		}

		// Normalize the path by removing leading slashes
		normalizedPath := strings.TrimPrefix(header.Name, "/")

		// Check if this is our target binary (expect it in the root)
		if normalizedPath == binaryName || header.Name == binaryName {
			// Check if it's a regular file
			if header.Typeflag != tar.TypeReg {
				logger.Debug("found target but not a regular file", "name", header.Name, "type", header.Typeflag)
				continue
			}

			logger.Info("found plugin binary in OCI image", "entry", header.Name, "size", header.Size)

			// Create the output file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}

			// Copy the binary data
			_, err = io.Copy(outFile, tarReader)
			outFile.Close() //nolint:errcheck
			if err != nil {
				removeErr := os.Remove(targetPath)
				if removeErr != nil {
					return errors.Join(fmt.Errorf("failed to extract binary data: %w", err), fmt.Errorf("failed to remove %s: %w", targetPath, err))
				}
				return fmt.Errorf("failed to extract binary data: %w", err)
			}

			// Set executable permissions
			if err := os.Chmod(targetPath, 0o755); err != nil {
				logger.Warn("failed to set executable permissions", "path", targetPath, "error", err)
			}

			logger.Debug("successfully extracted plugin binary", "path", targetPath, "size", header.Size)
			return nil
		}
	}

	return fmt.Errorf("binary %q not found in root of OCI image", binaryName)
}
