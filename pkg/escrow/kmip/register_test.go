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

// TestNewKMIPAgentFromConfig_EmptyEndpoint proves an AgentConfig with no
// endpoint is refused by the translated KMIPConfig's own validation, the
// same as calling NewKMIPAgent directly, rather than the adapter
// swallowing the error or constructing an unusable agent.
func TestNewKMIPAgentFromConfig_EmptyEndpoint(t *testing.T) {
	_, err := newKMIPAgentFromConfig(&escrow.AgentConfig{Type: escrow.AgentTypeKMIP})
	assert.ErrorIs(t, err, escrow.ErrEmptyEndpoint)
}

// TestNewAgent_DispatchesToKMIPFactory proves the registration this
// package's init() performs (escrow.RegisterAgentFactory) is actually wired
// end to end: escrow.NewAgent given Type: "kmip" reaches this package's
// factory and returns a *KMIPAgent, not ErrUnknownAgentType, with the
// escrow.AgentConfig fields carried into its KMIPConfig.
func TestNewAgent_DispatchesToKMIPFactory(t *testing.T) {
	cfg := &escrow.AgentConfig{
		Type:     escrow.AgentTypeKMIP,
		Endpoint: "kmip://escrow.example.com:5696",
		Timeout:  7 * time.Second,
	}

	agent, err := escrow.NewAgent(cfg)
	require.NoError(t, err)

	kmipAgent, ok := agent.(*KMIPAgent)
	require.True(t, ok, "expected *KMIPAgent from escrow.NewAgent, got %T", agent)
	assert.Equal(t, cfg.Endpoint, kmipAgent.config.Endpoint)
	assert.Equal(t, cfg.Timeout, kmipAgent.config.Timeout)
}
