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

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/authzscan"
)

// TestMethodPermissions_ScanMatchesWireContract is the authzscan counterpart
// of TestMethodPermissions_MatchOtherTransports (authz_test.go): that test
// compares the runtime methodPermissions map's *values* against
// goldenMethodPermissions, which catches a repointed or widened permission
// but not a raw string literal that happens to carry the same value as the
// constant it replaced — Go evaluates "sign" and auth.ActionSign to the same
// string, so a value comparison cannot tell them apart. authzscan.ScanMap
// reads methodPermissions out of this package's own source instead, so it
// rejects a literal the moment it sees one (*authzscan.RawLiteralError),
// exactly as pkg/api/grpc's and pkg/api/rest's call-site goldens do for
// their own gates. Reusing goldenMethodPermissions here, rather than a
// second hand-maintained table, keeps the two tests from drifting apart.
func TestMethodPermissions_ScanMatchesWireContract(t *testing.T) {
	sites, err := authzscan.ScanMap(".", "methodPermissions")
	require.NoError(t, err, "scanning this package's methodPermissions map must succeed")

	require.Len(t, sites, len(goldenMethodPermissions),
		"an entry was added to or removed from methodPermissions without updating the wire contract")

	found := make(map[string]string, len(sites))
	for _, site := range sites {
		_, dup := found[site.Key]
		require.False(t, dup, "duplicate method key %q at %s", site.Key, site.Pos)
		found[site.Key] = site.Pair()
	}

	for method, want := range goldenMethodPermissions {
		got, ok := found[method]
		require.True(t, ok, "method %q lost its methodPermissions entry", method)
		assert.Equal(t, want, got, "method %q", method)
	}

	for method, got := range found {
		want, ok := goldenMethodPermissions[method]
		require.True(t, ok, "method %q gained a methodPermissions entry without a wire-contract entry", method)
		assert.Equal(t, want, got, "method %q", method)
	}
}

// TestMethodPermissions_NoRawLiterals proves no entry in methodPermissions
// spells its resource or action as a string literal. authzscan.ScanMap
// returns a *authzscan.RawLiteralError the moment it sees one, so a
// successful scan is the proof. This is the regression guard go-xkms#1232
// added: pkg/api/rest/routes.go carried this exact defect (raw "derive",
// "wrap", "unwrap" literals) with no test that would have caught it here.
func TestMethodPermissions_NoRawLiterals(t *testing.T) {
	sites, err := authzscan.ScanMap(".", "methodPermissions")
	require.NoError(t, err, "every methodPermissions entry must name a pkg/auth constant, never a string literal")
	require.NotEmpty(t, sites)
}
