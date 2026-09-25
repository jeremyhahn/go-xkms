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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestHandleBootstrapShowKeys covers the bootstrap.showKeys handler's two
// states: not yet published, and published with a full response.
func TestHandleBootstrapShowKeys(t *testing.T) {
	t.Run("returns error when no listener has published keys", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		req := makeReq("bootstrap.showKeys", nil)
		_, err := server.handleBootstrapShowKeys(context.Background(), req)
		require.Error(t, err)
		assert.ErrorIs(t, err, xkms.ErrBootstrapListenerNotEnabled)

		// go-xkms#930: the refusal must reach dispatch as a *KeyOpError
		// carrying ErrCodeServiceUnavailable, matching
		// pkg/api/grpc/service_bootstrap.go's mapBootstrapError
		// (codes.Unavailable), not a bare sentinel error.
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	})

	t.Run("returns the published keys", func(t *testing.T) {
		server := createTestServer(t)
		defer cleanupXKMS()

		server.xkmsService.SetBootstrapListenerKeys(&transport.BootstrapListenerKeysResponse{
			NoisePublicKey: "aa",
		})

		req := makeReq("bootstrap.showKeys", nil)
		result, err := server.handleBootstrapShowKeys(context.Background(), req)
		require.NoError(t, err)

		resp, ok := result.(*transport.BootstrapListenerKeysResponse)
		require.True(t, ok)
		assert.Equal(t, "aa", resp.NoisePublicKey)
	})
}
