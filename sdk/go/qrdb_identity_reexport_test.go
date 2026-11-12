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

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestReexport_QRDBIdentity pins that the sdk/go identity names and
// pkg/auth share one context key, so xkey tests can move from pkg/auth to
// QRDBIdentity / QRDBWithIdentity without changing what servers read.
func TestReexport_QRDBIdentity(t *testing.T) {
	id := &QRDBIdentity{Subject: "alice", TenantID: "t1", Roles: []string{"operator"}}

	ctx := QRDBWithIdentity(context.Background(), id)
	require.Same(t, id, auth.GetIdentity(ctx))

	other := &auth.Identity{Subject: "bob", TenantID: "t2", Roles: []string{"auditor"}}
	ctx = auth.WithIdentity(context.Background(), other)
	require.Same(t, other, QRDBIdentityFromContext(ctx))
}
