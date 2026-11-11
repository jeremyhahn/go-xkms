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

package xkms

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Importing this package registers the federation agent under the "xkms"
// type, and the escrow factory builds it from the generic agent config.
func TestNewAgent_XKMSTypeBuildsFederationAgent(t *testing.T) {
	agent, err := escrow.NewAgent(&escrow.AgentConfig{
		Type:     escrow.AgentTypeXKMS,
		Endpoint: "https://dr-xkms.company.com:8443",
		Timeout:  5 * time.Second,
	})
	require.NoError(t, err)

	federation, ok := agent.(*FederationAgent)
	require.True(t, ok, "the xkms type must build a *FederationAgent")
	assert.Equal(t, "https://dr-xkms.company.com:8443", federation.endpoint)
	assert.Equal(t, 5*time.Second, federation.client.Timeout)
}

// A config the federation agent rejects surfaces its error through the
// factory with no agent: a nil interface, not one holding a nil pointer.
func TestNewAgent_XKMSTypeRejectsUnreadableCA(t *testing.T) {
	agent, err := escrow.NewAgent(&escrow.AgentConfig{
		Type:     escrow.AgentTypeXKMS,
		Endpoint: "https://dr-xkms.company.com:8443",
		CACert:   "/nonexistent/ca.pem",
	})
	require.ErrorIs(t, err, escrow.ErrAuthenticationFailed)
	assert.True(t, agent == nil, "the factory must return a nil EscrowAgent, got %#v", agent)
}
