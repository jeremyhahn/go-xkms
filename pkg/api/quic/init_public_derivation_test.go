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

package quic

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/initgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQUICInitGate_DerivedFromCanonicalTable asserts the QUIC transport's
// public ceremony allowlist is exactly the initgate derivation — the guard
// that keeps a hand-mirrored copy from ever being reintroduced.
func TestQUICInitGate_DerivedFromCanonicalTable(t *testing.T) {
	assert.Equal(t, initgate.HTTPPublicPaths(), publicCeremonyPaths,
		"QUIC publicCeremonyPaths must be the initgate derivation, not a hand-maintained copy")
}

// TestQUICInitGate_ExactHistoricalSet locks the QUIC exemption to the exact
// five paths this transport has always exempted, with sign-csr excluded.
func TestQUICInitGate_ExactHistoricalSet(t *testing.T) {
	want := map[string]bool{
		"/api/v1/init/status":               true,
		"/api/v1/init/claim-cert/begin":     true,
		"/api/v1/init/claim-cert/complete":  true,
		"/api/v1/init/claim-share/begin":    true,
		"/api/v1/init/claim-share/complete": true,
	}
	require.Equal(t, want, publicCeremonyPaths)
	assert.False(t, publicCeremonyPaths["/api/v1/init/sign-csr"],
		"sign-csr requires the SO PIN and must never be exempt")
}

// TestQUICInitGate_NoPrefixEntries guards against prefix-match
// reintroduction on the QUIC allowlist.
func TestQUICInitGate_NoPrefixEntries(t *testing.T) {
	for p := range publicCeremonyPaths {
		assert.Falsef(t, strings.HasSuffix(p, "/"),
			"allowlist entry %q ends in '/': prefix matching is forbidden", p)
	}
}
