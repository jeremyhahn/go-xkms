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

package unix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// TestTPMPolicy_ReachesTheServer proves a connected transport serves the TPM
// policy API over its gRPC connection: the request's tenant and name reach
// the server and its policy is decoded. The conversions themselves are
// tested once, in pkg/api/grpc/pbconv.
func TestTPMPolicy_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	p, err := tr.TPMPolicyGet(context.Background(), &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "acme", p.TenantID)
	assert.Equal(t, []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}, p.Branches)
	assert.True(t, p.Approved)
}

// TestTPMPolicy_NotConnected proves every TPM policy method refuses before
// the transport is connected.
func TestTPMPolicy_NotConnected(t *testing.T) {
	for name, call := range tpmpolicytest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
