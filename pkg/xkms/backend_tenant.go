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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
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
func (t *TenantScopedBackend) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GenerateRSA(ctx, t.scopeAttrs(attrs))
}

// GenerateECDSA generates a new ECDSA key pair scoped to this tenant.
func (t *TenantScopedBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GenerateECDSA(ctx, t.scopeAttrs(attrs))
}

// GenerateEd25519 generates a new Ed25519 key pair scoped to this tenant.
func (t *TenantScopedBackend) GenerateEd25519(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GenerateEd25519(ctx, t.scopeAttrs(attrs))
}

// GetKey retrieves a key scoped to this tenant.
func (t *TenantScopedBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.GetKey(ctx, t.scopeAttrs(attrs))
}

// DeleteKey removes a key scoped to this tenant.
func (t *TenantScopedBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return t.base.DeleteKey(ctx, t.scopeAttrs(attrs))
}

// ListKeys returns all keys managed by the underlying backend.
// Filtering by tenant is left to the underlying key provider via TenantID on KeyAttributes;
// here we return the full list as the provider itself handles namespace isolation.
func (t *TenantScopedBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	all, err := t.base.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	// A tenant-scoped view must only ever show that tenant's keys. Returning
	// the unfiltered set would let a lookup by common name — which is how
	// findKeyAttrs resolves a key ID — match another tenant's key, since a CN
	// is only unique within a tenant.
	scoped := make([]*types.KeyAttributes, 0, len(all))
	for _, attr := range all {
		if attr != nil && attr.TenantID == t.tenantID {
			scoped = append(scoped, attr)
		}
	}
	return scoped, nil
}

// RotateKey replaces an existing key scoped to this tenant.
func (t *TenantScopedBackend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return t.base.RotateKey(ctx, t.scopeAttrs(attrs))
}

// ========================================================================
// Crypto Operations
// ========================================================================

// Signer returns a crypto.Signer for the specified key, scoped to this tenant.
func (t *TenantScopedBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return t.base.Signer(ctx, t.scopeAttrs(attrs))
}

// Decrypter returns a crypto.Decrypter for the specified key, scoped to this tenant.
func (t *TenantScopedBackend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return t.base.Decrypter(ctx, t.scopeAttrs(attrs))
}

// ========================================================================
// Certificate Operations
// ========================================================================

// SaveCert stores a certificate under the tenant-scoped key ID.
func (t *TenantScopedBackend) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	return t.base.SaveCert(ctx, t.scopeCertKeyID(keyID), cert)
}

// GetCert retrieves a certificate by tenant-scoped key ID.
func (t *TenantScopedBackend) GetCert(ctx context.Context, keyID string) (*x509.Certificate, error) {
	return t.base.GetCert(ctx, t.scopeCertKeyID(keyID))
}

// DeleteCert removes a certificate by tenant-scoped key ID.
func (t *TenantScopedBackend) DeleteCert(ctx context.Context, keyID string) error {
	return t.base.DeleteCert(ctx, t.scopeCertKeyID(keyID))
}

// SaveCertChain stores a certificate chain under the tenant-scoped key ID.
func (t *TenantScopedBackend) SaveCertChain(ctx context.Context, keyID string, chain []*x509.Certificate) error {
	return t.base.SaveCertChain(ctx, t.scopeCertKeyID(keyID), chain)
}

// GetCertChain retrieves a certificate chain by tenant-scoped key ID.
func (t *TenantScopedBackend) GetCertChain(ctx context.Context, keyID string) ([]*x509.Certificate, error) {
	return t.base.GetCertChain(ctx, t.scopeCertKeyID(keyID))
}

// ListCerts returns all certificate IDs from the underlying backend.
func (t *TenantScopedBackend) ListCerts(ctx context.Context) ([]string, error) {
	all, err := t.base.ListCerts(ctx)
	if err != nil {
		return nil, err
	}

	// Every other certificate method addresses storage through scopeCertKeyID,
	// so the listing must apply the same namespace and hand back the
	// tenant-relative key IDs the caller uses everywhere else.
	prefix := t.tenantID + "/"
	scoped := make([]string, 0, len(all))
	for _, keyID := range all {
		if strings.HasPrefix(keyID, prefix) {
			scoped = append(scoped, strings.TrimPrefix(keyID, prefix))
		}
	}
	return scoped, nil
}

// CertExists checks if a certificate exists under the tenant-scoped key ID.
func (t *TenantScopedBackend) CertExists(ctx context.Context, keyID string) (bool, error) {
	return t.base.CertExists(ctx, t.scopeCertKeyID(keyID))
}

// ========================================================================
// TLS Helpers
// ========================================================================

// GetTLSCertificate returns a tls.Certificate using the tenant-scoped key ID.
func (t *TenantScopedBackend) GetTLSCertificate(ctx context.Context, keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return t.base.GetTLSCertificate(ctx, t.scopeCertKeyID(keyID), t.scopeAttrs(attrs))
}

// ========================================================================
// Unified Key ID Methods
// ========================================================================

// GetKeyByID retrieves a key using the unified Key ID format.
func (t *TenantScopedBackend) GetKeyByID(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	return t.base.GetKeyByID(ctx, keyID)
}

// GetSignerByID retrieves a crypto.Signer using the unified Key ID format.
func (t *TenantScopedBackend) GetSignerByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	return t.base.GetSignerByID(ctx, keyID)
}

// GetDecrypterByID retrieves a crypto.Decrypter using the unified Key ID format.
func (t *TenantScopedBackend) GetDecrypterByID(ctx context.Context, keyID string) (crypto.Decrypter, error) {
	return t.base.GetDecrypterByID(ctx, keyID)
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
// Import/Export Operations
// ========================================================================
//
// These methods make the tenant wrapper offer the import/export capability
// itself, so the one operation that takes key material from outside is scoped
// exactly like every other key operation. Before them the capability was only
// reachable through KeyProvider(), which returns the base provider and
// discards the wrapper — a tenant's import landed on the untenanted
// identifier, could silently collide with an untenanted key of the same name,
// and was invisible to the importing tenant's own ListKeys (go-xkms#163).

// importExporter returns the base backend's import/export capability, or the
// typed refusal when the base's key provider does not implement
// backend.ImportExportBackend.
func (t *TenantScopedBackend) importExporter() (ImportExporter, error) {
	importExport, ok := importExportFor(t.base)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrImportExportNotSupported,
			Detail:   "tenant-scoped base backend does not support import/export operations",
		}
	}
	return importExport, nil
}

// GetImportParameters retrieves import parameters for a key scoped to this
// tenant.
func (t *TenantScopedBackend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	importExport, err := t.importExporter()
	if err != nil {
		return nil, err
	}
	return importExport.GetImportParameters(ctx, t.scopeAttrs(attrs), algorithm)
}

// WrapKey wraps key material for secure transport. The material carries no
// key attributes, so there is nothing to scope; the call still routes through
// the capability so a scoped backend answers it the same way an unscoped one
// does.
func (t *TenantScopedBackend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	importExport, err := t.importExporter()
	if err != nil {
		return nil, err
	}
	return importExport.WrapKey(ctx, keyMaterial, params)
}

// UnwrapKey unwraps key material previously wrapped with WrapKey. As with
// WrapKey there are no key attributes to scope.
func (t *TenantScopedBackend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	importExport, err := t.importExporter()
	if err != nil {
		return nil, err
	}
	return importExport.UnwrapKey(ctx, wrapped, params)
}

// ImportKey imports externally generated key material scoped to this tenant.
// The stamped TenantID reaches the stored identifier and the key's metadata
// record, so the import is visible to — and only to — the tenant that made it.
func (t *TenantScopedBackend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	importExport, err := t.importExporter()
	if err != nil {
		return err
	}
	return importExport.ImportKey(ctx, t.scopeAttrs(attrs), wrapped)
}

// ExportKey exports a key in wrapped form, scoped to this tenant.
func (t *TenantScopedBackend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	importExport, err := t.importExporter()
	if err != nil {
		return nil, err
	}
	return importExport.ExportKey(ctx, t.scopeAttrs(attrs), algorithm)
}

// ExportKeyMaterial returns raw key material for an extractable symmetric key
// scoped to this tenant.
func (t *TenantScopedBackend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	importExport, err := t.importExporter()
	if err != nil {
		return nil, err
	}
	return importExport.ExportKeyMaterial(ctx, t.scopeAttrs(attrs))
}

// ========================================================================
// Lifecycle
// ========================================================================

// Type returns the base backend's store type. It reaches Type() without
// unwrapping to KeyProvider(), so asking a tenant-scoped view what kind of
// backend it is does not require discarding the tenant scope to get the
// answer (go-xkms#163, go-xkms#312).
func (t *TenantScopedBackend) Type() types.StoreType {
	return t.base.Type()
}

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
