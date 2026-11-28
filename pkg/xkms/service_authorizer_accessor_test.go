// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestAuthorizer_NilUnlessEnabled proves the accessor never hands out an
// authorizer that allows everything: with no authorizer wired, or with one
// that has no RBAC client, it is the nil interface, not a typed nil.
func TestAuthorizer_NilUnlessEnabled(t *testing.T) {
	t.Run("none wired", func(t *testing.T) {
		svc := &XKMSService{}
		assert.True(t, svc.Authorizer() == nil, "want the nil interface")
	})

	t.Run("disabled", func(t *testing.T) {
		svc := &XKMSService{}
		svc.SetAuthorizer(auth.NewAuthorizer(nil))
		assert.True(t, svc.Authorizer() == nil, "want the nil interface")
	})

	t.Run("nil service", func(t *testing.T) {
		var svc *XKMSService
		assert.True(t, svc.Authorizer() == nil, "want the nil interface")
	})
}

// TestAuthorizer_ReturnsTheWiredAuthorizer proves an enabled authorizer is
// returned as is and enforces the RBAC client's grants.
func TestAuthorizer_ReturnsTheWiredAuthorizer(t *testing.T) {
	rbac := &recordingRBAC{grant: "audit:read"}
	wired := auth.NewAuthorizer(rbac)
	svc := &XKMSService{}
	svc.SetAuthorizer(wired)

	got := svc.Authorizer()
	require.NotNil(t, got)
	assert.Same(t, wired, got)

	id := &auth.Identity{Subject: "alice", TenantID: "acme"}
	require.NoError(t, got.Authorize(context.Background(), id, "audit", "read"))
	require.ErrorIs(t, got.Authorize(context.Background(), id, "audit", "delete"), errGrantMissing)
}
