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

package quic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
)

// TestOIDCCredential_ReachesTheServer proves a connected transport serves
// the OIDC credential API over the REST routes: the scope and name travel in
// the path, the tenant and owner in the query, and the server's answer is
// decoded. The routes and bodies of every method are tested once, in
// pkg/api/rest/wire.
func TestOIDCCredential_ReachesTheServer(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	ctx := context.Background()
	ref := &transport.OIDCCredentialRef{TenantID: "acme", Scope: transport.OIDCCredentialScopeUser, Owner: "alice", Name: "codex"}

	c, err := tr.OIDCCredentialGet(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, *ref, c.OIDCCredentialRef)
	assert.Equal(t, transport.OIDCCredentialStatusActive, c.Status)

	tok, err := tr.OIDCCredentialGetAccessToken(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "at-alice", tok.AccessToken)
}

// TestOIDCCredential_RefusesANilRequest proves a nil request is refused
// before anything is sent.
func TestOIDCCredential_RefusesANilRequest(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	_, err := tr.OIDCCredentialGetAccessToken(context.Background(), nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, tr.OIDCCredentialDelete(context.Background(), nil), wire.ErrNilRequest)
}

// TestOIDCCredential_NotConnected proves every OIDC credential method
// refuses before the transport is connected.
func TestOIDCCredential_NotConnected(t *testing.T) {
	for name, call := range oidccredentialtest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
