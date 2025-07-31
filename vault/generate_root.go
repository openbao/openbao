// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/roottoken"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
)

// GenerateStandardRootTokenStrategy is the strategy used to generate a
// typical root token
var GenerateStandardRootTokenStrategy GenerateRootStrategy = generateStandardRootToken{}

// GenerateRootStrategy allows us to swap out the strategy we want to use to
// create a token upon completion of the generate root process.
type GenerateRootStrategy interface {
	generate(context.Context, *Core) (string, func(), error)
	authenticate(context.Context, *Core, []byte) error
}

// generateStandardRootToken implements the GenerateRootStrategy and is in
// charge of creating standard root tokens.
type generateStandardRootToken struct{}

func (g generateStandardRootToken) authenticate(ctx context.Context, c *Core, combinedKey []byte) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	nsSeal, found := c.sealManager.sealsByNamespace[ns.UUID]["default"]
	if !found {
		return fmt.Errorf("no seal found for namespace")
	}
	rootKey, err := c.sealManager.unsealKeyToRootKey(ctx, nsSeal, combinedKey, false)
	if err != nil {
		return fmt.Errorf("unable to authenticate: %w", err)
	}
	nsBarrier, ok := c.sealManager.barrierByNamespace.Get(ns.Path)
	if !ok {
		return fmt.Errorf("failed to accquire barrier for namespace %q", ns.Path)
	}
	if err := nsBarrier.(SecurityBarrier).VerifyRoot(rootKey); err != nil {
		return fmt.Errorf("root key verification failed: %w", err)
	}

	return nil
}

func (g generateStandardRootToken) generate(ctx context.Context, c *Core) (string, func(), error) {
	te, err := c.tokenStore.rootToken(ctx)
	if err != nil {
		c.logger.Error("root token generation failed", "error", err)
		return "", nil, err
	}
	if te == nil {
		c.logger.Error("got nil token entry back from root generation")
		return "", nil, errors.New("got nil token entry back from root generation")
	}

	cleanupFunc := func() {
		c.tokenStore.revokeOrphan(ctx, te.ID)
	}

	return te.ExternalID, cleanupFunc, nil
}

// GenerateRootConfig holds the configuration for a root generation
// command.
type GenerateRootConfig struct {
	Nonce          string
	PGPKey         string
	PGPFingerprint string
	OTP            string
	Strategy       GenerateRootStrategy
}

// GenerateRootResult holds the result of a root generation update
// command
type GenerateRootResult struct {
	Progress       int
	Required       int
	EncodedToken   string
	PGPFingerprint string
}

// GenerateRootProgress is used to return the root generation progress (num shares)
func (c *Core) GenerateRootProgress(ns *namespace.Namespace) (int, error) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return 0, consts.ErrSealed
	}
	if c.standby.Load() && !c.recoveryMode {
		return 0, consts.ErrStandby
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	if c.namespaceRootGens[ns.UUID] == nil {
		return 0, nil
	}

	return len(c.namespaceRootGens[ns.UUID].Progress), nil
}

// GenerateRootConfiguration is used to read the root generation configuration
// It stubbornly refuses to return the OTP if one is there.
func (c *Core) GenerateRootConfiguration(ns *namespace.Namespace) (*GenerateRootConfig, error) {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return nil, consts.ErrSealed
	}
	if c.standby.Load() && !c.recoveryMode {
		return nil, consts.ErrStandby
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	namespaceRootGen, ok := c.namespaceRootGens[ns.UUID]
	if !ok {
		return nil, nil
	}

	config := *namespaceRootGen.Config
	config.OTP = ""
	config.Strategy = nil

	return &config, nil
}

// GenerateRootInit is used to initialize the root generation settings
func (c *Core) GenerateRootInit(otp, pgpKey string, strategy GenerateRootStrategy, ns *namespace.Namespace) error {
	var fingerprint string
	switch {
	case len(otp) > 0:
		var expectedLength int
		if ns.UUID == namespace.RootNamespaceUUID {
			expectedLength = TokenLength
		} else {
			expectedLength = NSTokenLength
		}

		if c.DisableSSCTokens() {
			expectedLength += OldTokenPrefixLength
		} else {
			expectedLength += TokenPrefixLength
		}

		if len(otp) != expectedLength {
			return errors.New("OTP string is wrong length")
		}
	case len(pgpKey) > 0:
		fingerprints, err := pgpkeys.GetFingerprints([]string{pgpKey}, nil)
		if err != nil {
			return fmt.Errorf("error parsing PGP key: %w", err)
		}
		if len(fingerprints) != 1 || fingerprints[0] == "" {
			return errors.New("could not acquire PGP key entity")
		}
		fingerprint = fingerprints[0]

	default:
		return errors.New("otp or pgp_key parameter must be provided")
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	if c.Sealed() && !c.recoveryMode {
		return consts.ErrSealed
	}
	barrierSealed := c.barrier.Sealed()
	if !barrierSealed && c.recoveryMode {
		return errors.New("attempt to generate recovery operation token when already unsealed")
	}
	if c.standby.Load() && !c.recoveryMode {
		return consts.ErrStandby
	}

	nsRootGen, exists := c.namespaceRootGens[ns.UUID]
	if !exists {
		nsRootGen = &NamespaceRootGeneration{}
		c.namespaceRootGens[ns.UUID] = nsRootGen
	}

	nsRootGen.Lock.Lock()
	defer nsRootGen.Lock.Unlock()

	// Prevent multiple concurrent root generations per namespace
	if nsRootGen.Config != nil {
		return errors.New("root generation already in progress for this namespace")
	}

	// Copy the configuration
	generationNonce, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}

	nsRootGen.Config = &GenerateRootConfig{
		Nonce:          generationNonce,
		OTP:            otp,
		PGPKey:         pgpKey,
		PGPFingerprint: fingerprint,
		Strategy:       strategy,
	}

	if c.logger.IsInfo() {
		switch strategy.(type) {
		case generateStandardRootToken:
			c.logger.Info("root generation initialized", "nonce", nsRootGen.Config.Nonce)
		case *generateRecoveryToken:
			c.logger.Info("recovery operation token generation initialized", "nonce", nsRootGen.Config.Nonce)
		default:
			c.logger.Info("dr operation token generation initialized", "nonce", nsRootGen.Config.Nonce)
		}
	}

	return nil
}

// GenerateRootUpdate is used to provide a new key part for the root token generation.
func (c *Core) GenerateRootUpdate(ctx context.Context, key []byte, nonce string, strategy GenerateRootStrategy) (*GenerateRootResult, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	barrier, found := c.sealManager.barrierByNamespace.Get(ns.Path)
	if !found {
		return nil, fmt.Errorf("barrier not found for namespace: %q", ns.Path)
	}

	// Verify the key length
	min, max := barrier.(SecurityBarrier).KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	// Get the seal configuration
	var config *SealConfig

	seal, found := c.sealManager.sealsByNamespace[ns.UUID]["default"]
	if !found {
		return nil, fmt.Errorf("no seal found for namespace")
	}
	if seal.RecoveryKeySupported() {
		config, err = seal.RecoveryConfig(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		config, err = seal.Config(ctx)
		if err != nil {
			return nil, err
		}
	}

	// Ensure the barrier is initialized
	if config == nil {
		return nil, ErrNotInit
	}

	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return nil, consts.ErrSealed
	}

	barrierSealed := c.barrier.Sealed()
	if !barrierSealed && c.recoveryMode {
		return nil, errors.New("attempt to generate recovery operation token when already unsealed")
	}

	if c.standby.Load() && !c.recoveryMode {
		return nil, consts.ErrStandby
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	nsRootGen, exists := c.namespaceRootGens[ns.UUID]
	if !exists {
		return nil, fmt.Errorf("no current active root generation for namespace %s", ns.Path)
	}

	// Ensure a generateRoot is in progress
	if nsRootGen.Config == nil {
		return nil, fmt.Errorf("no root generation in progress for namespace %s", ns.Path)
	}

	if nonce != nsRootGen.Config.Nonce {
		return nil, fmt.Errorf("incorrect nonce supplied; nonce for this root generation operation is %q", nsRootGen.Config.Nonce)
	}

	if strategy != nsRootGen.Config.Strategy {
		return nil, errors.New("incorrect strategy supplied; a generate root operation of another type is already in progress")
	}

	// Check if we already have this piece
	for _, existing := range nsRootGen.Progress {
		if bytes.Equal(existing, key) {
			return nil, errors.New("given key has already been provided during this generation operation")
		}
	}

	nsRootGen.Progress = append(nsRootGen.Progress, key)
	progress := len(nsRootGen.Progress)

	if progress < config.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot generate root, not enough keys", "keys", progress, "threshold", config.SecretThreshold)
		}
		return &GenerateRootResult{
			Progress:       progress,
			Required:       config.SecretThreshold,
			PGPFingerprint: nsRootGen.Config.PGPFingerprint,
		}, nil
	}

	// Combine the key parts
	var combinedKey []byte
	if config.SecretThreshold == 1 {
		combinedKey = nsRootGen.Progress[0]
		nsRootGen.Progress = nil
	} else {
		combinedKey, err = shamir.Combine(nsRootGen.Progress)
		nsRootGen.Progress = nil
		if err != nil {
			return nil, fmt.Errorf("failed to compute root key: %w", err)
		}
	}

	if err := strategy.authenticate(ctx, c, combinedKey); err != nil {
		c.logger.Error("root generation aborted", "error", err.Error())
		return nil, fmt.Errorf("root generation aborted: %w", err)
	}

	// Run the generate strategy
	token, cleanupFunc, err := strategy.generate(ctx, c)
	if err != nil {
		return nil, err
	}

	var encodedToken string

	switch {
	case len(nsRootGen.Config.OTP) > 0:
		encodedToken, err = roottoken.EncodeToken(token, nsRootGen.Config.OTP)
	case len(nsRootGen.Config.PGPKey) > 0:
		var tokenBytesArr [][]byte
		_, tokenBytesArr, err = pgpkeys.EncryptShares([][]byte{[]byte(token)}, []string{nsRootGen.Config.PGPKey})
		encodedToken = base64.StdEncoding.EncodeToString(tokenBytesArr[0])
	default:
		err = errors.New("unreachable condition")
	}

	if err != nil {
		cleanupFunc()
		return nil, err
	}

	results := &GenerateRootResult{
		Progress:       progress,
		Required:       config.SecretThreshold,
		EncodedToken:   encodedToken,
		PGPFingerprint: nsRootGen.Config.PGPFingerprint,
	}

	switch strategy.(type) {
	case generateStandardRootToken:
		c.logger.Info("root generation finished", "nonce", nsRootGen.Config.Nonce)
	case *generateRecoveryToken:
		c.logger.Info("recovery operation token generation finished", "nonce", nsRootGen.Config.Nonce)
	default:
		c.logger.Info("dr operation token generation finished", "nonce", nsRootGen.Config.Nonce)
	}

	delete(c.namespaceRootGens, ns.UUID)
	nsRootGen = nil

	return results, nil
}

// GenerateRootCancel is used to cancel an in-progress root generation
func (c *Core) GenerateRootCancel(ns *namespace.Namespace) error {
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()
	if c.Sealed() && !c.recoveryMode {
		return consts.ErrSealed
	}
	if c.standby.Load() && !c.recoveryMode {
		return consts.ErrStandby
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	// Clear any progress or config
	delete(c.namespaceRootGens, ns.UUID)

	return nil
}
