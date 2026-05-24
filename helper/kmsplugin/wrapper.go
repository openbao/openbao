// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	gkwplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/alicloudkms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/gcpckms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/kmip/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/ocikms/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/transit/v2"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/pluginutil/catalog"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

var builtinWrappers = map[wrapping.WrapperType]builtinWrapper{
	// Standards-based or generic:
	wrapping.WrapperTypeKmip:    {toWrapper(kmip.NewWrapper), false},
	wrapping.WrapperTypeStatic:  {toWrapper(static.NewWrapper), false},
	wrapping.WrapperTypeTransit: {toWrapper(transit.NewWrapper), false},

	// Cloud providers:
	wrapping.WrapperTypeAliCloudKms:   {toWrapper(alicloudkms.NewWrapper), true},
	wrapping.WrapperTypeAwsKms:        {toWrapper(awskms.NewWrapper), true},
	wrapping.WrapperTypeAzureKeyVault: {toWrapper(azurekeyvault.NewWrapper), true},
	wrapping.WrapperTypeGcpCkms:       {toWrapper(gcpckms.NewWrapper), true},
	wrapping.WrapperTypeOciKms:        {toWrapper(ocikms.NewWrapper), true},

	wrapping.WrapperTypePkcs11: {func() (wrapping.Wrapper, error) {
		// The real wrapper is conditionally enabled pkcs11.go.
		return nil, errors.New("this build of OpenBao has PKCS#11 disabled")
	}, false},
}

// builtinWrapper only exists to track deprecation status. This construct can be
// replaced with just wrapperFactory beyond OpenBao v2.6.
type builtinWrapper struct {
	factory    wrapperFactory
	deprecated bool
}

type wrapperFactory func() (wrapping.Wrapper, error)

// wrapperInitFinalizer is a joint wrapping.Wrapper & wrapping.InitFinalizer, as
// is always returned by go-kms-wrapping/plugin.
type wrapperInitFinalizer interface {
	wrapping.Wrapper
	wrapping.InitFinalizer
}

// toWrapper is a hack to go from func() <concrete wrapper type> to func()
// (wrapping.Wrapper, error), as constructors in go-kms-wrapping tend to return
// the concrete type.
func toWrapper[T wrapping.Wrapper](f func() T) wrapperFactory {
	return func() (wrapping.Wrapper, error) { return f(), nil }
}

type Catalog struct {
	*catalog.Catalog
}

func NewCatalog(logger hclog.Logger, config *server.Config) (*Catalog, error) {
	base, err := catalog.NewCatalog(
		logger,
		config,
		consts.PluginTypeKMS,
		gkwplugin.HandshakeConfig,
		gkwplugin.PluginSets,
	)
	if err != nil {
		return nil, err
	}

	return &Catalog{base}, nil
}

// ConfigureWrapper creates a new wrapper instance and calls SetConfig with
// the provided options. This may dispatch to either a builtin wrapper or an
// external pluginized wrapper.
func (c *Catalog) ConfigureWrapper(ctx context.Context, name string, opts ...wrapping.Option) (wrapping.Wrapper, *wrapping.WrapperConfig, error) {
	w, builtin, err := c.getWrapper(name)
	if err != nil {
		return nil, nil, err
	}

	config, err := w.SetConfig(ctx, opts...)
	if err != nil {
		// If we fail to configure the wrapper, ensure any underlying client is
		// closed to avoid leaking it.
		if w, ok := w.(*wrapper); ok {
			w.client.Close()
		}
		return nil, nil, err
	}

	// Enrich metadata by marking builtin vs externally provided wrappers.
	if config.Metadata == nil {
		config.Metadata = make(map[string]string, 1)
	}
	if builtin {
		config.Metadata["builtin"] = "true"
	} else {
		config.Metadata["builtin"] = "false"
	}

	return w, config, nil
}

// getWrapper returns a new wrapping.Wrapper that is either builtin or
// pluginized, in which case a new plugin process may be spawned. The
// additionally returned bool is true if the returned wrapper is built-in.
func (c *Catalog) getWrapper(name string) (wrapping.Wrapper, bool, error) {
	client, ok, err := c.GetClient(name)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		// Try builtin wrappers.
		if builtin, ok := builtinWrappers[wrapping.WrapperType(name)]; ok {
			w, err := builtin.factory()
			if builtin.deprecated {
				c.Logger.Warn("Support for this Auto Unseal mechanism has been "+
					"moved into an external plugin and will be removed from the "+
					"main OpenBao distribution in the next minor release. "+
					"To ensure future-proof use of this mechanism, migrate your "+
					"deployment to the fully compatible, drop-in plugin version. "+
					"For more information, see https://openbao.org/docs/release-notes/2-6-0/#v260", "seal", name)
			}
			return w, true, err
		}
		return nil, false, fmt.Errorf("unknown wrapper: %s", name)
	}

	// Each call to Dispense creates a new wrapper instance on the remote.
	raw, err := client.Dispense("wrapper")
	if err != nil {
		client.Close()
		return nil, false, err
	}

	return &wrapper{
		client:  client,
		wrapper: raw.(wrapperInitFinalizer),
	}, false, nil
}

// wrapper adds plugin reloading & finalization hooks on top of a pluginized
// wrapping.Wrapper.
type wrapper struct {
	mu sync.RWMutex

	client  *catalog.Client
	wrapper wrapperInitFinalizer

	configOpts, initOpts []wrapping.Option
}

// retry calls f and retries it once if interrupted by a plugin shutdown.
func (w *wrapper) retry(ctx context.Context, f func() error) error {
	canary, err := w.call(f)

	if err != gkwplugin.ErrPluginShutdown {
		// Plugin works and call either succeeded or returned an
		// application-level error.
		return err
	}

	// Try to reload the plugin & reinstantiate the wrapper.
	if err := w.reload(ctx, canary); err != nil {
		return err
	}

	// Then give this another shot.
	_, err = w.call(f)
	return err
}

// call is a helper to call f under a read lock and return the current client
// pointer as a reload canary value.
func (w *wrapper) call(f func() error) (*catalog.Client, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.client == nil {
		return nil, errors.New("wrapper was finalized")
	}

	return w.client, f()
}

// reload attempts to reload the underlying external plugin and reinstantiate
// the remote wrapper instance.
func (w *wrapper) reload(ctx context.Context, canary *catalog.Client) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.client == nil {
		return errors.New("wrapper was finalized")
	}

	if w.client != canary {
		// Another caller managed to reload before we got the lock.
		return nil
	}

	client, err := w.client.Reload()
	if err != nil {
		return err
	}

	raw, err := client.Dispense("wrapper")
	if err != nil {
		client.Close()
		return err
	}

	wrapper := raw.(wrapperInitFinalizer)
	if w.configOpts != nil {
		// Replay SetConfig if it was called on the original wrapper.
		if _, err := wrapper.SetConfig(ctx, w.configOpts...); err != nil {
			return err
		}
	}
	if w.initOpts != nil {
		// Replay Init if it was called on the original wrapper.
		if err := wrapper.Init(ctx, w.configOpts...); err != nil {
			return err
		}
	}

	// Only commit the reload if replays succeeded.
	w.client = client
	w.wrapper = wrapper

	return nil
}

func (w *wrapper) SetConfig(ctx context.Context, opts ...wrapping.Option) (config *wrapping.WrapperConfig, err error) {
	if err = w.retry(ctx, func() error {
		config, err = w.wrapper.SetConfig(ctx, opts...)
		return err
	}); err != nil {
		return nil, err
	}

	// Save these so SetConfig can be replayed when the plugin is reloaded. We
	// assume that locking is not needed as SetConfig calls should not be made
	// concurrently either way.
	w.configOpts = opts

	return config, nil
}

func (w *wrapper) Init(ctx context.Context, opts ...wrapping.Option) error {
	if err := w.retry(ctx, func() error {
		return w.wrapper.Init(ctx, opts...)
	}); err != nil {
		return err
	}

	// Save these so Init can be replayed when the plugin is reloaded. We assume
	// that locking is not needed as Init calls should not be made concurrently
	// either way.
	w.initOpts = opts

	return nil
}

func (w *wrapper) Finalize(ctx context.Context, opts ...wrapping.Option) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	defer func() {
		w.client.Close()
		// As a safety measure, set the client to nil to ensure the wrapper does
		// not reload & replay itself if any of its APIs are called after this
		// call to Finalize.
		w.client = nil
	}()

	// No need to retry Finalize, but ignore any plugin shutdown errors.
	switch err := w.wrapper.Finalize(ctx, opts...); err {
	case gkwplugin.ErrPluginShutdown:
		return nil
	default:
		return err
	}
}

func (w *wrapper) Type(ctx context.Context) (ty wrapping.WrapperType, err error) {
	err = w.retry(ctx, func() (err error) {
		ty, err = w.wrapper.Type(ctx)
		return err
	})
	return ty, err
}

func (w *wrapper) KeyId(ctx context.Context) (id string, err error) {
	err = w.retry(ctx, func() (err error) {
		id, err = w.wrapper.KeyId(ctx)
		return err
	})
	return id, err
}

func (w *wrapper) Encrypt(ctx context.Context, plaintext []byte, opts ...wrapping.Option) (blob *wrapping.BlobInfo, err error) {
	err = w.retry(ctx, func() (err error) {
		blob, err = w.wrapper.Encrypt(ctx, plaintext, opts...)
		return err
	})
	return blob, err
}

func (w *wrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, opts ...wrapping.Option) (plaintext []byte, err error) {
	err = w.retry(ctx, func() (err error) {
		plaintext, err = w.wrapper.Decrypt(ctx, blob, opts...)
		return err
	})
	return plaintext, err
}
