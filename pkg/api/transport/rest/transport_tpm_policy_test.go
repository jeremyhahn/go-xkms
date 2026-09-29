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

package rest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// TestTPMPolicy_ReachesTheServer proves a connected transport serves the TPM
// policy API over the REST routes: the policy name travels in the path and
// the tenant in the query, and the server's policy is decoded. The routes
// and bodies of every method are tested once, in pkg/api/rest/wire.
func TestTPMPolicy_ReachesTheServer(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)

	p, err := tr.TPMPolicyGet(context.Background(), &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "acme", p.TenantID)
	assert.Equal(t, []uint{7}, p.PCRs)
}

// TestTPMPolicy_NotConnected proves every TPM policy method refuses before
// the transport is connected.
func TestTPMPolicy_NotConnected(t *testing.T) {
	for name, call := range tpmpolicytest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
