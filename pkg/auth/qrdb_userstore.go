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
// the bound qrdb user via the server-side secondary index and projects it
// onto MTLSUser, carrying the user's permitted-method policy so the
// authenticator can enforce it.
//
// The user's role assignments are carried as the qrdb role IDs the user record
// holds, all of them, unmodified. That is go-qrdb's own identity contract: its
// authentication middleware overwrites Identity.Roles with the stored RoleIDs,
// and its authorizer resolves permissions by role ID. Projecting an ID to its
// role name (as this store once did, and only for the first role) produced an
// identity the authorizer could not resolve — "role: not found" — so every
// request it authenticated was denied (go-xkms#1069).
type QRDBUserStore struct {
	users qrdbtransport.UserClient
}

// NewQRDBUserStore wires the qrdb user client into a UserStore.
func NewQRDBUserStore(users qrdbtransport.UserClient) *QRDBUserStore {
	return &QRDBUserStore{users: users}
}

// GetByCertFingerprint resolves the qrdb user bound to the given SPKI
// thumbprint and projects it onto MTLSUser, carrying every assigned role ID.
func (s *QRDBUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error) {
	u, err := s.users.GetUserByCertThumbprint(ctx, fingerprint)
	if err != nil {
		return MTLSUser{}, err
	}

	return MTLSUser{
		Username: u.Username,
		Email:    u.Email,
		Roles:    append([]string(nil), u.RoleIDs...),
		TenantID: u.TenantID,
		// Lifecycle is qrdb's only account state; only active authenticates.
		Enabled:     u.Lifecycle == string(qrdbsdk.LifecycleActive),
		AuthMethods: u.AuthMethods,
	}, nil
}
