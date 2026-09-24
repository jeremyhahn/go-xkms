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

package apimodule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetBackendRoundTrip_RealServer proves the client's "xkms.getBackend"
// call (go-xkms#762) reaches a real server-side handler, driving the
// production client transport against a real mcp-go server built from the
// real Module.RegisterMCP wiring. docs/crypto-backends/api.md already
// documented this method; before this change the server registered no
// handler for it at all, so every call failed to route.
func TestGetBackendRoundTrip_RealServer(t *testing.T) {
	addr := startRoundTripMCPServer(t)
	tr := connectRoundTripClient(t, addr)
	ctx := context.Background()

	info, err := tr.GetBackend(ctx, "software")
	require.NoError(t, err)
	assert.Equal(t, "software", info.ID)
}
