package jwtauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testProviderConfig struct {
	initialized string
	throwError  bool
}

func (t *testProviderConfig) Initialize(_ context.Context, jc *jwtConfig) error {
	if t.throwError {
		return fmt.Errorf("i'm throwing an error")
	}
	t.initialized = jc.ProviderConfig["initialized_value"].(string)
	return nil
}

func (t *testProviderConfig) SensitiveKeys() []string {
	return []string{"these", "are", "secret"}
}

func TestNewProviderConfig(t *testing.T) {

	t.Run("normal case", func(t *testing.T) {
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"provider":          "test",
				"initialized_value": "yes",
			},
		}
		pMap := map[string]CustomProvider{
			"test": &testProviderConfig{},
		}

		theProvider, err := NewProviderConfig(context.Background(), jc, pMap)
		assert.NoError(t, err)
		assert.Equal(t, "yes", theProvider.(*testProviderConfig).initialized)

		assert.Len(t, theProvider.SensitiveKeys(), 3)
		assert.Equal(t, []string{"these", "are", "secret"}, theProvider.SensitiveKeys())
	})

	t.Run("no provider_config", func(t *testing.T) {
		jc := &jwtConfig{}
		pMap := map[string]CustomProvider{
			"test": &testProviderConfig{},
		}

		theProvider, err := NewProviderConfig(context.Background(), jc, pMap)
		assert.NoError(t, err)
		assert.Nil(t, theProvider)
	})

	t.Run("provider field not present in provider_config", func(t *testing.T) {
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"initialized_value": "yes",
			},
		}
		pMap := map[string]CustomProvider{
			"test": &testProviderConfig{},
		}

		theProvider, err := NewProviderConfig(context.Background(), jc, pMap)
		assert.EqualError(t, err, "'provider' field not found in provider_config")
		assert.Nil(t, theProvider)
	})

	t.Run("unknown provider", func(t *testing.T) {
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"provider":          "test",
				"initialized_value": "yes",
			},
		}
		pMap := map[string]CustomProvider{
			"not-test": &testProviderConfig{},
		}

		theProvider, err := NewProviderConfig(context.Background(), jc, pMap)
		assert.EqualError(t, err, "provider \"test\" not found in custom providers")
		assert.Nil(t, theProvider)
	})

	t.Run("provider name not present in provider_config", func(t *testing.T) {
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"initialized_value": "yes",
			},
		}
		pMap := map[string]CustomProvider{
			"test": &testProviderConfig{},
		}

		theProvider, err := NewProviderConfig(context.Background(), jc, pMap)
		assert.EqualError(t, err, "'provider' field not found in provider_config")
		assert.Nil(t, theProvider)
	})

	t.Run("error in Initialize", func(t *testing.T) {
		jc := &jwtConfig{
			ProviderConfig: map[string]interface{}{
				"provider":          "test",
				"initialized_value": "yes",
			},
		}
		pMap := map[string]CustomProvider{
			"test": &testProviderConfig{throwError: true},
		}

		theProvider, err := NewProviderConfig(context.Background(), jc, pMap)
		assert.EqualError(t, err, "error initializing \"test\" provider_config: i'm throwing an error")
		assert.Nil(t, theProvider)
	})
}
