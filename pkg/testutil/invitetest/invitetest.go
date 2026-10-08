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

// Package invitetest gives tests a real, tenant-routed invitation store in
// the shape xkms.InviteStore declares. go-qrdb's TenantInviteStore owns every
// invitation semantic, but its Create takes creation options the SDK does not
// re-export, so it does not satisfy xkms.InviteStore directly. Production
// composes its store through pkg/compose, which imports pkg/xkms; this
// package imports only the qrdb SDK, so pkg/xkms's own tests and the
// transports' tests can use it without an import cycle.
package invitetest

import (
	"context"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Store is go-qrdb's TenantInviteStore with an option-less Create. Lookup
// and Redeem are the embedded store's own.
type Store struct {
	*qrdbsdk.TenantInviteStore
}

// New builds a Store that routes each tenant's invitations through resolver.
func New(resolver qrdbsdk.TenantStoreResolver) (*Store, error) {
	inner, err := qrdbsdk.NewTenantInviteStore(resolver)
	if err != nil {
		return nil, err
	}
	return &Store{TenantInviteStore: inner}, nil
}

// Create issues an invitation for userID in tenantID with go-qrdb's default
// creation options and returns the plaintext token.
func (s *Store) Create(ctx context.Context, userID, tenantID string, ttl time.Duration) (string, *qrdbsdk.InviteEntity, error) {
	return s.TenantInviteStore.Create(ctx, userID, tenantID, ttl)
}
