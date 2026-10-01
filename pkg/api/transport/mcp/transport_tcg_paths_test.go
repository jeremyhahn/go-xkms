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
)

// TestResolveMethod_TCGCanonicalPaths proves the MCP transport maps the
// canonical TCG CA paths (/api/v1/ca/tcg/*, the server's REST routes) onto
// their tools, and no longer knows the stale /api/v1/tcg-ca/* spelling.
func TestResolveMethod_TCGCanonicalPaths(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/ca/tcg/ek":       "xkms.ca.tcg.issue-ek",
		"/api/v1/ca/tcg/ak":       "xkms.ca.tcg.issue-ak",
		"/api/v1/ca/tcg/sign-csr": "xkms.ca.tcg.sign-csr",
		"/api/v1/ca/tcg/enroll":   "xkms.ca.tcg.enroll",
	} {
		got, ok := resolveMethod(path)
		assert.True(t, ok, path)
		assert.Equal(t, want, got, path)
	}
	_, ok := resolveMethod("/api/v1/tcg-ca/issue-ek-cert")
	assert.False(t, ok, "the stale TCG CA path is gone")
}
