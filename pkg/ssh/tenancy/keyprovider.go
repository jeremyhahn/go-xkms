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

package tenancy

import (
	"context"
	"crypto"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tenantKeyProvider is a tenant partition's view of a crypto backend's
// KeyProvider: every key it generates, loads, signs with, rotates or deletes
// is addressed with types.KeyAttributes.TenantID set to its tenant, so the
// backend namespaces it (types.KeyAttributes.ID prefixes the tenant) exactly
// as xkms.TenantScopedBackend does for the key-management surface. A backend
// key's common name is unique only within a tenant; without this view two
// tenants naming the same SSH key would address the same backend key.
//
// The view does not own base, which the backend registry shares with every
// other caller.
type tenantKeyProvider struct {
	base     types.KeyProvider
	tenantID string
}

var _ types.KeyProvider = (*tenantKeyProvider)(nil)

// scoped returns a copy of attrs addressed in the view's tenant. The
// caller's attributes are never mutated.
func (p *tenantKeyProvider) scoped(attrs *types.KeyAttributes) *types.KeyAttributes {
	if attrs == nil {
		return nil
	}
	tenanted := *attrs
	tenanted.TenantID = p.tenantID
	return &tenanted
}

// Type implements types.KeyProvider.
func (p *tenantKeyProvider) Type() types.BackendType { return p.base.Type() }

// Capabilities implements types.KeyProvider.
func (p *tenantKeyProvider) Capabilities() types.Capabilities { return p.base.Capabilities() }

// GenerateKey implements types.KeyProvider in the view's tenant.
func (p *tenantKeyProvider) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return p.base.GenerateKey(ctx, p.scoped(attrs))
}

// GetKey implements types.KeyProvider in the view's tenant.
func (p *tenantKeyProvider) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return p.base.GetKey(ctx, p.scoped(attrs))
}

// DeleteKey implements types.KeyProvider in the view's tenant.
func (p *tenantKeyProvider) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return p.base.DeleteKey(ctx, p.scoped(attrs))
}

// ListKeys implements types.KeyProvider: only the view's tenant's keys.
func (p *tenantKeyProvider) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	all, err := p.base.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	owned := make([]*types.KeyAttributes, 0, len(all))
	for _, attrs := range all {
		if attrs != nil && attrs.TenantID == p.tenantID {
			owned = append(owned, attrs)
		}
	}
	return owned, nil
}

// Signer implements types.KeyProvider in the view's tenant.
func (p *tenantKeyProvider) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return p.base.Signer(ctx, p.scoped(attrs))
}

// Decrypter implements types.KeyProvider in the view's tenant.
func (p *tenantKeyProvider) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return p.base.Decrypter(ctx, p.scoped(attrs))
}

// RotateKey implements types.KeyProvider in the view's tenant.
func (p *tenantKeyProvider) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return p.base.RotateKey(ctx, p.scoped(attrs))
}

// Close implements types.KeyProvider. The view owns nothing -- base belongs
// to the backend registry and stays open for its other callers -- so there is
// nothing to release.
func (p *tenantKeyProvider) Close() error { return nil }
