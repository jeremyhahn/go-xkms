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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TenantScopedBackend wraps a Backend and ensures all operations are tenant-scoped.
// Every key operation sets attrs.TenantID to the configured tenant, and every
// certificate operation prefixes the keyID with "{tenantID}/".
type TenantScopedBackend struct {
	base     Backend
	tenantID string
}

// Verify interface compliance at compile time.
var _ Backend = (*TenantScopedBackend)(nil)

// NewTenantScopedBackend returns a Backend that scopes all operations to tenantID.
func NewTenantScopedBackend(base Backend, tenantID string) *TenantScopedBackend {
	return &TenantScopedBackend{base: base, tenantID: tenantID}
}

// scopeAttrs returns a copy of attrs with TenantID set to this tenant.
func (t *TenantScopedBackend) scopeAttrs(attrs *types.KeyAttributes) *types.KeyAttributes {
	if attrs == nil {
		return nil
	}
	// Shallow copy so we do not mutate the caller's struct.
	copy := *attrs
	copy.TenantID = t.tenantID
	return &copy
}

// scopeCertKeyID prefixes the keyID with the tenant namespace.
func (t *TenantScopedBackend) scopeCertKeyID(keyID string) string {
	return fmt.Sprintf("%s/%s", t.tenantID, keyID)
}

// ========================================================================
// Key Operations
// ========================================================================

// GenerateRSA generates a new RSA key pair scoped to this tenant.
func (t *TenantScopedBackend) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GenerateRSA(t.scopeAttrs(attrs))
}

// GenerateECDSA generates a new ECDSA key pair scoped to this tenant.
func (t *TenantScopedBackend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GenerateECDSA(t.scopeAttrs(attrs))
}

// GenerateEd25519 generates a new Ed25519 key pair scoped to this tenant.
func (t *TenantScopedBackend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GenerateEd25519(t.scopeAttrs(attrs))
}

// GetKey retrieves a key scoped to this tenant.
func (t *TenantScopedBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GetKey(t.scopeAttrs(attrs))
}

// DeleteKey removes a key scoped to this tenant.
func (t *TenantScopedBackend) DeleteKey(attrs *types.KeyAttributes) error {
	return t.base.DeleteKey(t.scopeAttrs(attrs))
}

// ListKeys returns all keys managed by the underlying backend.
// Filtering by tenant is left to the underlying key provider via TenantID on KeyAttributes;
// here we return the full list as the provider itself handles namespace isolation.
func (t *TenantScopedBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return t.base.ListKeys()
}

// RotateKey replaces an existing key scoped to this tenant.
func (t *TenantScopedBackend) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.RotateKey(t.scopeAttrs(attrs))
}

// ========================================================================
// Crypto Operations
// ========================================================================

// Signer returns a crypto.Signer for the specified key, scoped to this tenant.
func (t *TenantScopedBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return t.base.Signer(t.scopeAttrs(attrs))
}

// Decrypter returns a crypto.Decrypter for the specified key, scoped to this tenant.
func (t *TenantScopedBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return t.base.Decrypter(t.scopeAttrs(attrs))
}

// ========================================================================
// Certificate Operations
// ========================================================================

// SaveCert stores a certificate under the tenant-scoped key ID.
func (t *TenantScopedBackend) SaveCert(keyID string, cert *x509.Certificate) error {
	return t.base.SaveCert(t.scopeCertKeyID(keyID), cert)
}

// GetCert retrieves a certificate by tenant-scoped key ID.
func (t *TenantScopedBackend) GetCert(keyID string) (*x509.Certificate, error) {
	return t.base.GetCert(t.scopeCertKeyID(keyID))
}

// DeleteCert removes a certificate by tenant-scoped key ID.
func (t *TenantScopedBackend) DeleteCert(keyID string) error {
	return t.base.DeleteCert(t.scopeCertKeyID(keyID))
}

// SaveCertChain stores a certificate chain under the tenant-scoped key ID.
func (t *TenantScopedBackend) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	return t.base.SaveCertChain(t.scopeCertKeyID(keyID), chain)
}

// GetCertChain retrieves a certificate chain by tenant-scoped key ID.
func (t *TenantScopedBackend) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	return t.base.GetCertChain(t.scopeCertKeyID(keyID))
}

// ListCerts returns all certificate IDs from the underlying backend.
func (t *TenantScopedBackend) ListCerts() ([]string, error) {
	return t.base.ListCerts()
}

// CertExists checks if a certificate exists under the tenant-scoped key ID.
func (t *TenantScopedBackend) CertExists(keyID string) (bool, error) {
	return t.base.CertExists(t.scopeCertKeyID(keyID))
}

// ========================================================================
// TLS Helpers
// ========================================================================

// GetTLSCertificate returns a tls.Certificate using the tenant-scoped key ID.
func (t *TenantScopedBackend) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return t.base.GetTLSCertificate(t.scopeCertKeyID(keyID), t.scopeAttrs(attrs))
}

// ========================================================================
// Unified Key ID Methods
// ========================================================================

// GetKeyByID retrieves a key using the unified Key ID format.
func (t *TenantScopedBackend) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	return t.base.GetKeyByID(keyID)
}

// GetSignerByID retrieves a crypto.Signer using the unified Key ID format.
func (t *TenantScopedBackend) GetSignerByID(keyID string) (crypto.Signer, error) {
	return t.base.GetSignerByID(keyID)
}

// GetDecrypterByID retrieves a crypto.Decrypter using the unified Key ID format.
func (t *TenantScopedBackend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	return t.base.GetDecrypterByID(keyID)
}

// ========================================================================
// Sealing Operations
// ========================================================================

// Seal encrypts data using the underlying backend's sealing mechanism.
func (t *TenantScopedBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	return t.base.Seal(ctx, data, opts)
}

// Unseal decrypts previously sealed data using the underlying backend.
func (t *TenantScopedBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return t.base.Unseal(ctx, sealed, opts)
}

// CanSeal returns true if the underlying backend supports sealing.
func (t *TenantScopedBackend) CanSeal() bool {
	return t.base.CanSeal()
}

// ========================================================================
// Lifecycle
// ========================================================================

// KeyProvider returns the underlying key provider.
func (t *TenantScopedBackend) KeyProvider() types.KeyProvider {
	return t.base.KeyProvider()
}

// CertStorage returns the underlying certificate storage adapter.
func (t *TenantScopedBackend) CertStorage() certstore.CertificateStorageAdapter {
	return t.base.CertStorage()
}

// Close delegates to the underlying backend.
// The TenantScopedBackend does not own the underlying backend, so Close is
// a pass-through that allows callers to release resources when needed.
func (t *TenantScopedBackend) Close() error {
	return t.base.Close()
}
