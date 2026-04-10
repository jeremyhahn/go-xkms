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

package user

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Compile-time interface check.
var _ auth.UserStore = (*MTLSUserStoreAdapter)(nil)

// MTLSUserStoreAdapter adapts a user.Store to the auth.UserStore interface
// used by the mTLS authenticator for certificate-to-user lookups.
type MTLSUserStoreAdapter struct {
	store Store
}

// NewMTLSUserStoreAdapter creates a new adapter wrapping the given user store.
func NewMTLSUserStoreAdapter(store Store) *MTLSUserStoreAdapter {
	return &MTLSUserStoreAdapter{store: store}
}

// GetByCertFingerprint looks up a user by the SHA-256 fingerprint of a client
// certificate's DER-encoded Raw bytes and returns an auth.MTLSUser.
// If no matching binding is found, ErrCertBindingNotFound is propagated.
func (a *MTLSUserStoreAdapter) GetByCertFingerprint(ctx context.Context, fingerprint string) (auth.MTLSUser, error) {
	u, err := a.store.GetByCertFingerprint(ctx, fingerprint)
	if err != nil {
		return auth.MTLSUser{}, err
	}
	return auth.MTLSUser{
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		Enabled:     u.Enabled,
	}, nil
}
