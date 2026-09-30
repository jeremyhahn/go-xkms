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
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// TestTPMPolicy_CallsTheTool proves the TPM policy methods call their MCP
// tools with the request as parameters and decode the result: the request's
// tenant and name reach the server, and a tenant-ID method sends tenant_id.
func TestTPMPolicy_CallsTheTool(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	ctx := context.Background()

	p, err := tr.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "acme", p.TenantID)
	assert.Equal(t, []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}, p.Branches)
	assert.True(t, p.Approved)

	st, err := tr.TenantVTPMStatus(ctx, "globex")
	require.NoError(t, err)
	assert.Equal(t, "globex", st.TenantID)
	assert.True(t, st.Running)
}

// TestTPMPolicy_NotConnected proves every TPM policy method refuses before it
// is connected.
func TestTPMPolicy_NotConnected(t *testing.T) {
	for name, call := range tpmpolicytest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
