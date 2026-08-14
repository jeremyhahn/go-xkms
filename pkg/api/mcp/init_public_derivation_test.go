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

package mcp

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMCPInitGate_DerivedFromCanonicalTable asserts the MCP transport's
// public ceremony allowlist is exactly the initgate derivation — the guard
// that keeps a hand-mirrored copy from ever being reintroduced.
func TestMCPInitGate_DerivedFromCanonicalTable(t *testing.T) {
	assert.Equal(t, initgate.MCPPublicMethods(), publicCeremonyMethods,
		"MCP publicCeremonyMethods must be the initgate derivation, not a hand-maintained copy")
}

// TestMCPInitGate_ExactHistoricalSet locks the MCP exemption to the exact
// five methods this transport has always exempted, with init.signCSR
// excluded.
func TestMCPInitGate_ExactHistoricalSet(t *testing.T) {
	want := map[string]struct{}{
		"init.getStatus":          {},
		"init.claimCertBegin":     {},
		"init.claimCertComplete":  {},
		"init.claimShareBegin":    {},
		"init.claimShareComplete": {},
	}
	require.Equal(t, want, publicCeremonyMethods)
	_, exempt := publicCeremonyMethods["init.signCSR"]
	assert.False(t, exempt, "init.signCSR requires the SO PIN and must never be exempt")
}
