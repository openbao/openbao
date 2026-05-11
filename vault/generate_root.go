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

type rootTokenGeneration struct {
	Config   *GenerateRootConfig
	Progress [][]byte
}

// GenerateStandardRootTokenStrategy is the strategy used to
// generate a typical root token.
var GenerateStandardRootTokenStrategy GenerateRootStrategy = generateStandardRootToken{}

// ErrNoRootGeneration is returned when no root token generation
// is currently in progress.
var ErrNoRootGeneration = errors.New("no root generation in progress")

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

	return c.sealManager.AuthenticateRootKey(ctx, ns, combinedKey)
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

// GenerateRootConfig holds the configuration for a root token generation.
type GenerateRootConfig struct {
	Nonce          string
	PGPKey         string
	PGPFingerprint string
	OTP            string
	Strategy       GenerateRootStrategy
}

// GenerateRootResult holds the result of a root token generation update.
type GenerateRootResult struct {
	Progress       int
	Required       int
	EncodedToken   string
	PGPFingerprint string
}

// lockRootGeneration is used to lock the stateLock of the Core,
// check the seal, standby and recoveryMode statuses, and return
// back an unlock func.
func (c *Core) lockRootGeneration() (func(), error) {
	c.stateLock.RLock()

	if c.Sealed() && !c.recoveryMode {
		c.stateLock.RUnlock()
		return nil, consts.ErrSealed
	}
	if c.standby.Load() && !c.recoveryMode {
		c.stateLock.RUnlock()
		return nil, consts.ErrStandby
	}
	if !c.barrier.Sealed() && c.recoveryMode {
		c.stateLock.RUnlock()
		return nil, errors.New("attempted to generate recovery operation token when already unsealed")
	}

	return c.stateLock.RUnlock, nil
}

// GenerateRootProgress is used to return the root token generation progress.
func (c *Core) GenerateRootProgress(ctx context.Context) (int, error) {
	unlock, err := c.lockRootGeneration()
	if err != nil {
		return 0, err
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return 0, err
	}

	c.namespaceRootGenLock.RLock()
	defer c.namespaceRootGenLock.RUnlock()

	if c.namespaceRootGens[ns.UUID] == nil {
		return 0, nil
	}

	return len(c.namespaceRootGens[ns.UUID].Progress), nil
}

// GenerateRootConfiguration is used to read the root generation configuration.
// It stubbornly refuses to return the OTP if one is there.
func (c *Core) GenerateRootConfiguration(ctx context.Context) (*GenerateRootConfig, error) {
	unlock, err := c.lockRootGeneration()
	if err != nil {
		return nil, err
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	c.namespaceRootGenLock.RLock()
	defer c.namespaceRootGenLock.RUnlock()

	namespaceRootGen, exists := c.namespaceRootGens[ns.UUID]
	if !exists {
		return nil, ErrNoRootGeneration
	}

	config := *namespaceRootGen.Config
	config.OTP = ""
	config.Strategy = nil

	return &config, nil
}

// GenerateRootInit is used to initialize the root generation attempt.
func (c *Core) GenerateRootInit(ctx context.Context, otp, pgpKey string, strategy GenerateRootStrategy) error {
	unlock, err := c.lockRootGeneration()
	if err != nil {
		return err
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

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
			return errors.New("OTP string has incorrect length")
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

	gen, exists := c.namespaceRootGens[ns.UUID]
	if !exists {
		gen = &rootTokenGeneration{}
		c.namespaceRootGens[ns.UUID] = gen
	}

	// Prevent multiple concurrent root generations per namespace.
	if gen.Config != nil {
		return errors.New("root generation already in progress for this namespace")
	}

	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}

	gen.Config = &GenerateRootConfig{
		Nonce:          nonce,
		OTP:            otp,
		PGPKey:         pgpKey,
		PGPFingerprint: fingerprint,
		Strategy:       strategy,
	}

	if c.logger.IsInfo() {
		switch strategy.(type) {
		case generateStandardRootToken:
			c.logger.Info("root generation initialized", "nonce", gen.Config.Nonce)
		case *generateRecoveryToken:
			c.logger.Info("recovery operation token generation initialized", "nonce", gen.Config.Nonce)
		default:
			c.logger.Info("dr operation token generation initialized", "nonce", gen.Config.Nonce)
		}
	}

	return nil
}

// GenerateRootUpdate is used to provide a new key part to progress root generation.
func (c *Core) GenerateRootUpdate(ctx context.Context, key []byte, nonce string, strategy GenerateRootStrategy) (*GenerateRootResult, error) {
	unlock, err := c.lockRootGeneration()
	if err != nil {
		return nil, err
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	barrier := c.sealManager.NamespaceBarrier(ns.Path)
	if barrier == nil {
		return nil, ErrNotSealable
	}

	// Verify the key length
	min, max := barrier.KeyLength()
	max += shamir.ShareOverhead
	if len(key) < min {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is shorter than minimum %d bytes", min)}
	}
	if len(key) > max {
		return nil, &ErrInvalidKey{fmt.Sprintf("key is longer than maximum %d bytes", max)}
	}

	seal := c.sealManager.NamespaceSeal(ns.UUID)
	if seal == nil {
		return nil, ErrNotSealable
	}

	// Get the seal configuration
	var config *SealConfig
	if seal.RecoveryKeySupported() {
		config, err = seal.RecoveryConfig(ctx)
	} else {
		config, err = seal.BarrierConfig(ctx)
	}

	if err != nil {
		return nil, err
	}

	// Ensure the barrier is initialized
	if config == nil {
		return nil, ErrNotInit
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	gen, exists := c.namespaceRootGens[ns.UUID]
	if !exists {
		return nil, ErrNoRootGeneration
	}

	if nonce != gen.Config.Nonce {
		return nil, fmt.Errorf("incorrect nonce supplied; nonce for this root generation operation is %q", gen.Config.Nonce)
	}

	if strategy != gen.Config.Strategy {
		return nil, errors.New("incorrect strategy supplied; a generate root operation of another type is already in progress")
	}

	// Check if we already have this piece
	for _, existing := range gen.Progress {
		if bytes.Equal(existing, key) {
			return nil, errors.New("given key has already been provided during this generation operation")
		}
	}

	// Store this key
	gen.Progress = append(gen.Progress, key)
	progress := len(gen.Progress)

	// Check if we don't have enough keys to unlock
	if progress < config.SecretThreshold {
		if c.logger.IsDebug() {
			c.logger.Debug("cannot generate root, not enough keys", "keys", progress, "threshold", config.SecretThreshold)
		}
		return &GenerateRootResult{
			Progress:       progress,
			Required:       config.SecretThreshold,
			PGPFingerprint: gen.Config.PGPFingerprint,
		}, nil
	}

	// Combine the key parts
	var combinedKey []byte
	if config.SecretThreshold == 1 {
		combinedKey = gen.Progress[0]
		gen.Progress = nil
	} else {
		combinedKey, err = shamir.Combine(gen.Progress)
		gen.Progress = nil
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
	case len(gen.Config.OTP) > 0:
		encodedToken, err = roottoken.EncodeToken(token, gen.Config.OTP)
	case len(gen.Config.PGPKey) > 0:
		var tokenBytesArr [][]byte
		_, tokenBytesArr, err = pgpkeys.EncryptShares([][]byte{[]byte(token)}, []string{gen.Config.PGPKey})
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
		PGPFingerprint: gen.Config.PGPFingerprint,
	}

	switch strategy.(type) {
	case generateStandardRootToken:
		c.logger.Info("root generation finished", "nonce", gen.Config.Nonce)
	case *generateRecoveryToken:
		c.logger.Info("recovery operation token generation finished", "nonce", gen.Config.Nonce)
	default:
		c.logger.Info("dr operation token generation finished", "nonce", gen.Config.Nonce)
	}

	delete(c.namespaceRootGens, ns.UUID)
	return results, nil
}

// GenerateRootCancel is used to cancel an in-progress root generation
func (c *Core) GenerateRootCancel(ctx context.Context) error {
	unlock, err := c.lockRootGeneration()
	if err != nil {
		return err
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	c.namespaceRootGenLock.Lock()
	defer c.namespaceRootGenLock.Unlock()

	// Clear any progress or config
	delete(c.namespaceRootGens, ns.UUID)
	return nil
}
