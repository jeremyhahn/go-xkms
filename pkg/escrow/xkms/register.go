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
	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

func init() {
	escrow.RegisterAgentFactory(escrow.AgentTypeXKMS, newFederationAgentFromConfig)
}

// newFederationAgentFromConfig adapts an escrow.AgentConfig to the
// FederationConfig this package's NewFederationAgent expects. It is
// registered against escrow.AgentTypeXKMS so pkg/escrow.NewAgent can build a
// FederationAgent without importing this package directly (which would
// cycle, since this package already imports pkg/escrow).
func newFederationAgentFromConfig(cfg *escrow.AgentConfig) (escrow.EscrowAgent, error) {
	return NewFederationAgent(&FederationConfig{
		Endpoint:   cfg.Endpoint,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
		CACert:     cfg.CACert,
		Timeout:    cfg.Timeout,
	})
}
