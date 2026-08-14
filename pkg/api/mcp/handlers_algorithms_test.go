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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestHandleAlgorithms_Success proves the method is dispatchable and reports
// a real inventory rather than an empty shell.
func TestHandleAlgorithms_Success(t *testing.T) {
	server := newShareServer(t)

	_, ok := rpcMethodHandlers["xkms.algorithms"]
	require.True(t, ok, "xkms.algorithms must be dispatchable")

	result, err := server.handleAlgorithms(context.Background(),
		shareRequest(t, "xkms.algorithms", struct{}{}))
	require.NoError(t, err)

	resp, ok := result.(*transport.AlgorithmsResponse)
	require.True(t, ok, "handler must return *transport.AlgorithmsResponse, got %T", result)
	assert.NotEmpty(t, resp.Signing, "a build with a software backend must report signing algorithms")

	for _, a := range resp.Signing {
		assert.NotEmpty(t, a.Algorithm, "every entry must name its algorithm")
		assert.NotEmpty(t, a.Backends, "every entry must name the backends providing it")
	}
}

// TestAlgorithms_IsPublicMethod pins discovery as unauthenticated, matching
// the REST route it mirrors. It must be declared public rather than
// permission-mapped — being both is a contradiction the authz tests reject.
func TestAlgorithms_IsPublicMethod(t *testing.T) {
	_, public := publicMethods["xkms.algorithms"]
	assert.True(t, public, "xkms.algorithms must be declared public")

	_, mapped := methodPermissions["xkms.algorithms"]
	assert.False(t, mapped, "a public method must not also carry a permission")
}
