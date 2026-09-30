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
	"github.com/jeremyhahn/go-xkms/pkg/testutil/keyversiontest"
)

// TestKeyVersions_CallTheTools proves the key-version methods call their MCP
// tools with the request as parameters and decode the result.
func TestKeyVersions_CallTheTools(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	ctx := context.Background()

	listed, err := tr.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "signer", listed.KeyID)
	assert.Equal(t, uint32(2), listed.CurrentVersion)
	require.Len(t, listed.Versions, 2)

	retired, err := tr.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "signer", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), retired.Version)
	assert.Equal(t, transport.KeyVersionRetired, retired.State)

	rotated, err := tr.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "acme", rotated.TenantID)
	require.Len(t, rotated.Results, 1)
}

// TestKeyVersions_NotConnected proves every key-version method refuses
// before it is connected.
func TestKeyVersions_NotConnected(t *testing.T) {
	for name, call := range keyversiontest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
