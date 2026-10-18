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

// handlers_algorithms_test.go covers the MCP algorithm discovery method.
package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAlgorithms_IsPublicMethod pins discovery as unauthenticated, matching
// the REST route it mirrors. It must be declared public rather than
// permission-mapped — being both is a contradiction the authz tests reject.
func TestAlgorithms_IsPublicMethod(t *testing.T) {
	entry, ok := rpcMethods["xkms.algorithms"]
	require.True(t, ok, "xkms.algorithms must be registered")
	assert.True(t, entry.public(), "xkms.algorithms must be registered with handlePublic")
	assert.Empty(t, entry.perm, "a public method must not also carry a permission")
}
