// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package escrow

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAgentType/newFakeAgent register a throwaway factory so factory
// dispatch can be exercised without importing pkg/escrow/xkms or
// pkg/escrow/kmip (which would cycle back into this package).
const fakeAgentType = "factory-test-fake"

func init() {
	RegisterAgentFactory(fakeAgentType, func(cfg *AgentConfig) (EscrowAgent, error) {
		return newMockAgent(cfg.Type), nil
	})
}

func TestNewAgent_DispatchesRegisteredType(t *testing.T) {
	agent, err := NewAgent(&AgentConfig{Type: fakeAgentType, Endpoint: "https://escrow.example.com:8443"})
	require.NoError(t, err)
	require.NotNil(t, agent)
	assert.Equal(t, fakeAgentType, agent.Type())
}

func TestNewAgent_UnknownType(t *testing.T) {
	agent, err := NewAgent(&AgentConfig{Type: "does-not-exist", Endpoint: "https://escrow.example.com:8443"})
	require.Error(t, err)
	assert.Nil(t, agent)
	assert.True(t, errors.Is(err, ErrUnknownAgentType))
}

func TestNewAgent_NilConfig(t *testing.T) {
	agent, err := NewAgent(nil)
	require.Error(t, err)
	assert.Nil(t, agent)
	assert.True(t, errors.Is(err, ErrAgentNotConfigured))
}

func TestNewAgent_InvalidConfig(t *testing.T) {
	// Missing Endpoint fails AgentConfig.Validate before dispatch is
	// attempted, so an unregistered Type never even reaches the factory
	// lookup.
	agent, err := NewAgent(&AgentConfig{Type: fakeAgentType})
	require.Error(t, err)
	assert.Nil(t, agent)
	assert.True(t, errors.Is(err, ErrEmptyEndpoint))
}

func TestNewRegistryFromConfig_Disabled(t *testing.T) {
	registry, err := NewRegistryFromConfig(&Config{Enabled: false})
	require.NoError(t, err)
	assert.Nil(t, registry)
}

func TestNewRegistryFromConfig_Nil(t *testing.T) {
	registry, err := NewRegistryFromConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, registry)
}

func TestNewRegistryFromConfig_Success(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Agents: []AgentConfig{
			{Type: fakeAgentType, Name: "primary", Endpoint: "https://escrow-1.example.com:8443"},
			{Type: fakeAgentType, Name: "secondary", Endpoint: "https://escrow-2.example.com:8443"},
		},
	}

	registry, err := NewRegistryFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)
	defer registry.Close()

	assert.ElementsMatch(t, []string{"primary", "secondary"}, registry.Agents())
}

func TestNewRegistryFromConfig_UsesTypeWhenNameEmpty(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Agents: []AgentConfig{
			{Type: fakeAgentType, Endpoint: "https://escrow.example.com:8443"},
		},
	}

	registry, err := NewRegistryFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)
	defer registry.Close()

	agent, err := registry.Get(fakeAgentType)
	require.NoError(t, err)
	assert.NotNil(t, agent)
}

func TestNewRegistryFromConfig_NoAgentsConfigured(t *testing.T) {
	registry, err := NewRegistryFromConfig(&Config{Enabled: true})
	require.Error(t, err)
	assert.Nil(t, registry)
	assert.True(t, errors.Is(err, ErrNoAgentsConfigured))
}

func TestNewRegistryFromConfig_DuplicateNameFails(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Agents: []AgentConfig{
			{Type: fakeAgentType, Endpoint: "https://escrow-1.example.com:8443"},
			{Type: fakeAgentType, Endpoint: "https://escrow-2.example.com:8443"},
		},
	}

	registry, err := NewRegistryFromConfig(cfg)
	require.Error(t, err)
	assert.Nil(t, registry)
	assert.True(t, errors.Is(err, ErrAgentAlreadyRegistered))
}

func TestNewRegistryFromConfig_UnknownAgentType(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Agents: []AgentConfig{
			{Type: "does-not-exist", Endpoint: "https://escrow.example.com:8443"},
		},
	}

	registry, err := NewRegistryFromConfig(cfg)
	require.Error(t, err)
	assert.Nil(t, registry)
	assert.True(t, errors.Is(err, ErrUnknownAgentType))
}
