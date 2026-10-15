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
	resolve func(ctx context.Context, thumbprint string) (MTLSUser, error)
}

// CertUserResolver is go-qrdb's server-side certificate lookup: the user
// service an embedded node exposes (Node.UserService). It resolves a
// thumbprint in the tenant the context names without authorizing a caller,
// which is what an authenticator needs — the certificate is resolved before
// its holder is authenticated, so there is no caller identity to authorize.
type CertUserResolver interface {
	UserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbsdk.User, error)
}

// NewQRDBUserStore wires the qrdb user client into a UserStore.
func NewQRDBUserStore(users qrdbtransport.UserClient) *QRDBUserStore {
	return &QRDBUserStore{resolve: func(ctx context.Context, thumbprint string) (MTLSUser, error) {
		u, err := users.GetUserByCertThumbprint(ctx, thumbprint)
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
	}}
}

// NewQRDBServiceUserStore wires an embedded node's user service into a
// UserStore. Over an embedded node this is the lookup to use: the node's auth
// chain refuses an anonymous client call, and its service principal belongs
// to the system tenant, so a client lookup could never resolve a tenant
// user's certificate under qrdb's strict tenant isolation.
func NewQRDBServiceUserStore(users CertUserResolver) *QRDBUserStore {
	return &QRDBUserStore{resolve: func(ctx context.Context, thumbprint string) (MTLSUser, error) {
		u, err := users.UserByCertThumbprint(ctx, thumbprint)
		if err != nil {
			return MTLSUser{}, err
		}
		return MTLSUser{
			Username:    u.Username,
			Email:       u.Email,
			Roles:       append([]string(nil), u.RoleIDs...),
			TenantID:    u.TenantID,
			Enabled:     u.Lifecycle == qrdbsdk.LifecycleActive,
			AuthMethods: u.AuthMethods,
		}, nil
	}}
}

// GetByCertFingerprint resolves the qrdb user bound to the given SPKI
// thumbprint and projects it onto MTLSUser, carrying every assigned role ID.
func (s *QRDBUserStore) GetByCertFingerprint(ctx context.Context, fingerprint string) (MTLSUser, error) {
	return s.resolve(ctx, fingerprint)
}
