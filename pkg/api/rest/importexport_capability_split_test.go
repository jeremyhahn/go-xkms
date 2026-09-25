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

package rest

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/signing/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// importOnlyProvider implements types.KeyProvider and backend.ImportBackend by
// delegating to a *mockImportExportSymmetricBackend, but deliberately does NOT
// embed it -- embedding would promote ExportKey and ExportKeyMaterial too,
// which is exactly the shape this type exists to rule out. It models AWS
// KMS's real capability split at the interface level: import genuinely
// works, and export is not merely refused at runtime but absent from the
// type entirely, the way go-xkms#A2 found it before ExportKeyMaterial was
// added to the AWS KMS backend.
type importOnlyProvider struct {
	inner *mockImportExportSymmetricBackend
}

func (p *importOnlyProvider) Type() types.BackendType          { return p.inner.Type() }
func (p *importOnlyProvider) Capabilities() types.Capabilities { return p.inner.Capabilities() }
func (p *importOnlyProvider) Close() error                     { return p.inner.Close() }
func (p *importOnlyProvider) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return p.inner.ListKeys(ctx)
}
func (p *importOnlyProvider) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return p.inner.GenerateKey(ctx, attrs)
}
func (p *importOnlyProvider) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return p.inner.GetKey(ctx, attrs)
}
func (p *importOnlyProvider) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return p.inner.DeleteKey(ctx, attrs)
}
func (p *importOnlyProvider) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return p.inner.Signer(ctx, attrs)
}
func (p *importOnlyProvider) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return p.inner.Decrypter(ctx, attrs)
}
func (p *importOnlyProvider) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return p.inner.RotateKey(ctx, attrs)
}
func (p *importOnlyProvider) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return p.inner.GetImportParameters(ctx, attrs, algorithm)
}
func (p *importOnlyProvider) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return p.inner.WrapKey(ctx, keyMaterial, params)
}
func (p *importOnlyProvider) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return p.inner.UnwrapKey(ctx, wrapped, params)
}
func (p *importOnlyProvider) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	return p.inner.ImportKey(ctx, attrs, wrapped)
}

// Compile-time checks: importOnlyProvider satisfies exactly the import half,
// and (critically) does NOT satisfy backend.ExportBackend or the full
// backend.ImportExportBackend union -- if it did, this file would no longer
// test what it claims to.
var (
	_ types.KeyProvider     = (*importOnlyProvider)(nil)
	_ backend.ImportBackend = (*importOnlyProvider)(nil)
)

func TestImportOnlyProvider_DoesNotSatisfyExportBackend(t *testing.T) {
	var provider types.KeyProvider = &importOnlyProvider{inner: newMockImportExportSymmetricBackend()}
	_, ok := provider.(backend.ExportBackend)
	assert.False(t, ok, "importOnlyProvider must not satisfy backend.ExportBackend, or this test file no longer tests an AWS-KMS-shaped backend")
	_, ok = provider.(backend.ImportExportBackend)
	assert.False(t, ok, "importOnlyProvider must not satisfy the full backend.ImportExportBackend union either")
}

// importOnlyKeyStore wraps importOnlyProvider to implement xkms.Backend. It
// only needs to support what ImportKeyHandler and ExportKeyHandler read:
// KeyProvider() and ListKeys().
type importOnlyKeyStore struct {
	provider *importOnlyProvider
}

func newImportOnlyKeyStore() *importOnlyKeyStore {
	return &importOnlyKeyStore{provider: &importOnlyProvider{inner: newMockImportExportSymmetricBackend()}}
}

func (m *importOnlyKeyStore) KeyProvider() types.KeyProvider { return m.provider }
func (m *importOnlyKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}
func (m *importOnlyKeyStore) SignerStore() store.SignerStorer {
	return nil
}

// Type derives the store type from the wrapped provider's own BackendType,
// exactly as a real compositeBackend does, rather than hard-coding a value
// this fake would drift from.
func (m *importOnlyKeyStore) Type() types.StoreType {
	return types.ParseStoreType(string(m.provider.Type()))
}
func (m *importOnlyKeyStore) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.RSA
	return m.provider.GenerateKey(ctx, attrs)
}
func (m *importOnlyKeyStore) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.ECDSA
	return m.provider.GenerateKey(ctx, attrs)
}
func (m *importOnlyKeyStore) GenerateEd25519(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.Ed25519
	return m.provider.GenerateKey(ctx, attrs)
}
func (m *importOnlyKeyStore) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return m.provider.GetKey(ctx, attrs)
}
func (m *importOnlyKeyStore) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return m.provider.DeleteKey(ctx, attrs)
}
func (m *importOnlyKeyStore) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return m.provider.ListKeys(ctx)
}
func (m *importOnlyKeyStore) RotateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, m.provider.RotateKey(ctx, attrs)
}
func (m *importOnlyKeyStore) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return m.provider.Signer(ctx, attrs)
}
func (m *importOnlyKeyStore) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return m.provider.Decrypter(ctx, attrs)
}
func (m *importOnlyKeyStore) SaveCert(_ context.Context, keyID string, cert *x509.Certificate) error {
	return nil
}
func (m *importOnlyKeyStore) GetCert(_ context.Context, keyID string) (*x509.Certificate, error) {
	return nil, backend.ErrKeyNotFound
}
func (m *importOnlyKeyStore) DeleteCert(_ context.Context, keyID string) error { return nil }
func (m *importOnlyKeyStore) ListCerts(_ context.Context) ([]string, error)    { return nil, nil }
func (m *importOnlyKeyStore) CertExists(_ context.Context, keyID string) (bool, error) {
	return false, nil
}
func (m *importOnlyKeyStore) SaveCertChain(_ context.Context, keyID string, chain []*x509.Certificate) error {
	return nil
}
func (m *importOnlyKeyStore) GetCertChain(_ context.Context, keyID string) ([]*x509.Certificate, error) {
	return nil, backend.ErrKeyNotFound
}
func (m *importOnlyKeyStore) GetTLSCertificate(ctx context.Context, keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, backend.ErrKeyNotFound
}
func (m *importOnlyKeyStore) GetKeyByID(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (m *importOnlyKeyStore) GetSignerByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (m *importOnlyKeyStore) GetDecrypterByID(ctx context.Context, keyID string) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (m *importOnlyKeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	return nil, backend.ErrOperationNotSupported
}
func (m *importOnlyKeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return nil, backend.ErrOperationNotSupported
}
func (m *importOnlyKeyStore) CanSeal() bool { return false }
func (m *importOnlyKeyStore) Close() error  { return nil }

var _ xkms.Backend = (*importOnlyKeyStore)(nil)

// TestImportKeyHandler_ReachableWithoutExportSupport is the regression test
// for the exact defect A2 describes: a backend that genuinely supports only
// import (AWS KMS's real shape, once ExportKeyMaterial was missing) must not
// have its working import path blocked by a whole-interface assertion that
// also demands the export half it was never going to have. ImportKeyHandler
// now asserts backend.ImportBackend, so this backend is reachable.
func TestImportKeyHandler_ReachableWithoutExportSupport(t *testing.T) {
	xkms.Reset()
	ks := newImportOnlyKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"import-only": ks},
		DefaultBackend: "import-only",
	})
	require.NoError(t, err)
	t.Cleanup(xkms.Reset)

	ctx := newTestHandlerContext()

	body := `{"backend": "import-only", "key_id": "imported-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSAES_OAEP_SHA_256"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
	w := httptest.NewRecorder()

	ctx.ImportKeyHandler(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "import must succeed on a backend that only supports the import half: %s", w.Body.String())

	var resp ImportKeyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestExportKeyHandler_PrecisePer_CapabilityRefusal verifies that the SAME
// import-only backend refuses ExportKeyHandler with a precise, typed 501 --
// backend.ErrExportNotSupported -- rather than the old undifferentiated 400
// "backend does not support import/export operations", and rather than
// falling through to a 500.
func TestExportKeyHandler_PrecisePer_CapabilityRefusal(t *testing.T) {
	xkms.Reset()
	ks := newImportOnlyKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"import-only": ks},
		DefaultBackend: "import-only",
	})
	require.NoError(t, err)
	t.Cleanup(xkms.Reset)

	ctx := newTestHandlerContext()
	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

	body := `{"algorithm": "RSAES_OAEP_SHA_256"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/some-key/export?backend=import-only", strings.NewReader(body))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Contains(t, w.Body.String(), backend.ErrExportNotSupported.Error())
}
