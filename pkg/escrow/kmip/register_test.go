// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package kmip

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

// TestNewKMIPAgentFromConfig_TranslatesFields proves the escrow.AgentConfig
// -> KMIPConfig field mapping this package registers against
// escrow.AgentTypeKMIP carries every field NewKMIPAgent needs, using an
// endpoint scheme the client accepts without dialing (construction is
// eager only for config validation and local TLS material, never a network
// round-trip per NewKMIPAgent's contract).
func TestNewKMIPAgentFromConfig_TranslatesFields(t *testing.T) {
	cfg := &escrow.AgentConfig{
		Type:     escrow.AgentTypeKMIP,
		Endpoint: "kmip://escrow.example.com:5696",
		Timeout:  7 * time.Second,
	}

	agent, err := newKMIPAgentFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, agent)

	kmipAgent, ok := agent.(*KMIPAgent)
	require.True(t, ok, "expected *KMIPAgent, got %T", agent)
	assert.Equal(t, cfg.Endpoint, kmipAgent.config.Endpoint)
	assert.Equal(t, cfg.Timeout, kmipAgent.config.Timeout)
}

// TestNewKMIPAgentFromConfig_EmptyEndpoint proves an AgentConfig with no
// endpoint is refused by the translated KMIPConfig's own validation, the
// same as calling NewKMIPAgent directly, rather than the adapter
// swallowing the error or constructing an unusable agent.
func TestNewKMIPAgentFromConfig_EmptyEndpoint(t *testing.T) {
	agent, err := newKMIPAgentFromConfig(&escrow.AgentConfig{Type: escrow.AgentTypeKMIP})
	assert.ErrorIs(t, err, escrow.ErrEmptyEndpoint)
	// A rejected config yields a nil interface, not one holding a nil pointer.
	assert.True(t, agent == nil, "the factory must return a nil EscrowAgent, got %#v", agent)
}

// TestNewAgent_DispatchesToKMIPFactory proves the registration this
// package's init() performs (escrow.RegisterAgentFactory) is actually wired
// end to end: escrow.NewAgent given Type: "kmip" reaches this package's
// factory and returns a *KMIPAgent, not ErrUnknownAgentType.
func TestNewAgent_DispatchesToKMIPFactory(t *testing.T) {
	agent, err := escrow.NewAgent(&escrow.AgentConfig{
		Type:     escrow.AgentTypeKMIP,
		Endpoint: "kmip://escrow.example.com:5696",
	})
	require.NoError(t, err)

	_, ok := agent.(*KMIPAgent)
	assert.True(t, ok, "expected *KMIPAgent from escrow.NewAgent, got %T", agent)
}
