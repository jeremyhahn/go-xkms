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

package auth

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Compile-time assertion that QRDBUserStore satisfies the mTLS UserStore seam.
var _ UserStore = (*QRDBUserStore)(nil)

// QRDBUserStore resolves mTLS identities against the qrdb-hosted user store —
// the single source of identity for the stack. It satisfies UserStore for the
// MTLSAuthenticator: given a client certificate's SPKI thumbprint, it resolves
// the bound qrdb user via the server-side secondary index, maps the user's
// first role id to its role name, and carries the user's permitted-method
// policy so the authenticator can enforce it.
type QRDBUserStore struct {
	users qrdbtransport.UserClient
	roles qrdbtransport.RoleClient
}

// NewQRDBUserStore wires the qrdb user and role clients into a UserStore. Both
// clients are required; the role client resolves role-id references to the
// role names the authorizer matches on.
func NewQRDBUserStore(users qrdbtransport.UserClient, roles qrdbtransport.RoleClient) *QRDBUserStore {
	return &QRDBUserStore{users: users, roles: roles}
}

// GetByCertFingerprint resolves the qrdb user bound to the given SPKI
// thumbprint and projects it onto MTLSUser. The user's first role id is
// resolved to its role name; a resolution failure leaves the role empty rather
// than failing the lookup, so a valid cert binding still authenticates and
// authorization degrades closed at the authorizer.
func (s *QRDBUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error) {
	u, err := s.users.GetUserByCertThumbprint(ctx, fingerprint)
	if err != nil {
		return MTLSUser{}, err
	}

	role := ""
	if len(u.RoleIDs) > 0 {
		if r, rerr := s.roles.GetRole(ctx, u.RoleIDs[0]); rerr == nil {
			role = r.Name
		}
	}

	return MTLSUser{
		Username: u.Username,
		Email:    u.Email,
		Role:     role,
		TenantID: u.TenantID,
		// Lifecycle is qrdb's only account state; only active authenticates.
		Enabled:     u.Lifecycle == string(qrdbsdk.LifecycleActive),
		AuthMethods: u.AuthMethods,
	}, nil
}
