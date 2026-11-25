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

package rest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// TestBuildTokenIssuer_MintOnAuthEnforcingNode mints the token pair a public
// WebAuthn ceremony ends with, on the anonymous context of a public route,
// against a REAL qrdb node that enforces authentication. The refresh record
// is persisted through the node's KV, which refuses an anonymous context; the
// issuer's store runs as the node's service principal (ruling 742).
func TestBuildTokenIssuer_MintOnAuthEnforcingNode(t *testing.T) {
	node := barriertest.NewPrincipalNode(t)
	build := func(t *testing.T, bind func(context.Context) (context.Context, error)) error {
		t.Helper()
		issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
			Backend:     xkmsmocks.NewMockKeyStore(),
			BackendName: "test",
			QRDBClient:  node.Client(),
			CallContext: CallContextFunc(bind),
		})
		require.NoError(t, err)
		pair, err := issuer.Mint(context.Background(), &auth.Identity{Subject: "alice", TenantID: "system"})
		if err == nil {
			require.NotEmpty(t, pair.RefreshToken)
		}
		return err
	}

	t.Run("service principal", func(t *testing.T) {
		require.NoError(t, build(t, node.ServiceContext))
	})
	// The cause on main: the anonymous context is refused by the node.
	t.Run("anonymous context is refused", func(t *testing.T) {
		require.Error(t, build(t, nil))
	})
}
