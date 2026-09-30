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

package xkms

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests exercise the kid-based Simplified API (ExportKey, RotateKey,
// CopyKey, and the loadStoredKeyAttrs helper they share) against a REAL
// software.Backend, not a mock. A mock that never modeled per-key metadata
// would pass ExportKey regardless of whether #925 was fixed, because it
// never consulted Exportable at all -- these tests would not have caught
// the regression. Routing the calls through the real PKCS#8 key provider's
// metadata store (pkg/keyprovider/pkcs8) is what makes the assertions mean
// anything.

// setupRealSoftwareKID initializes a real, in-memory software-backed xkms
// service under the "software" name.
func setupRealSoftwareKID(t *testing.T) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	softwareBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	b, err := New(&BackendConfig{Backend: softwareBackend, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": b},
		DefaultBackend: "software",
	}))
	wireKeyVersionStore(t)
}

// generateKIDTestRSAKey generates a 2048-bit RSA signing key named cn on the
// registered "software" backend, with Exportable set as given.
func generateKIDTestRSAKey(t *testing.T, cn string, exportable bool) {
	t.Helper()
	b, err := GetBackend("software")
	require.NoError(t, err)

	_, err = b.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    exportable,
	})
	require.NoError(t, err)
}

// ------------------------------------------------------------------------
// loadStoredKeyAttrs
// ------------------------------------------------------------------------

func TestLoadStoredKeyAttrs_Success(t *testing.T) {
	setupRealSoftwareKID(t)
	generateKIDTestRSAKey(t, "kid-load-ok", true)

	b, err := GetBackend("software")
	require.NoError(t, err)

	attrs, err := loadStoredKeyAttrs(context.Background(), b, "kid-load-ok")
	require.NoError(t, err)
	assert.Equal(t, "kid-load-ok", attrs.CN)
	assert.True(t, attrs.Exportable, "the stored record's Exportable must be the one GenerateRSA persisted")
}

func TestLoadStoredKeyAttrs_NotFound(t *testing.T) {
	setupRealSoftwareKID(t)

	b, err := GetBackend("software")
	require.NoError(t, err)

	_, err = loadStoredKeyAttrs(context.Background(), b, "no-such-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ------------------------------------------------------------------------
// ExportKey
// ------------------------------------------------------------------------

// TestExportKeyByKID_ExportableTrue_Succeeds is the core #925 regression
// test: a key generated with Exportable: true must export by kid. Before the
// fix, ExportKey resolved attrs purely from ParseKeyIDToAttributes, whose
// Exportable is always the kid string's zero value, so this always failed.
func TestExportKeyByKID_ExportableTrue_Succeeds(t *testing.T) {
	setupRealSoftwareKID(t)
	generateKIDTestRSAKey(t, "kid-export-true", true)

	wrapped, err := ExportKey(context.Background(), "software:signing:rsa:kid-export-true", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped.WrappedKey)
}

func TestExportKeyByKID_ExportableFalse_Refused(t *testing.T) {
	setupRealSoftwareKID(t)
	generateKIDTestRSAKey(t, "kid-export-false", false)

	_, err := ExportKey(context.Background(), "software:signing:rsa:kid-export-false", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
}

func TestExportKeyByKID_UnknownKID_NotFound(t *testing.T) {
	setupRealSoftwareKID(t)

	_, err := ExportKey(context.Background(), "software:::does-not-exist", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ------------------------------------------------------------------------
// RotateKey
// ------------------------------------------------------------------------

// TestRotateKeyByKID_PreservesExportable pins RotateKey's documented
// contract ("replace with a newly generated key... with the same
// attributes"): a key rotated by kid must keep the Exportable it was created
// with. Before the fix, RotateKey regenerated using attrs reconstructed from
// the kid alone, which silently downgraded every rotated key to
// Exportable: false.
func TestRotateKeyByKID_PreservesExportable(t *testing.T) {
	setupRealSoftwareKID(t)
	generateKIDTestRSAKey(t, "kid-rotate-exportable", true)

	_, err := RotateKey(context.Background(), "software:signing:rsa:kid-rotate-exportable")
	require.NoError(t, err)

	// The rotation created version 2 as its own backend key; it must carry
	// the key's exportability.
	wrapped, err := ExportKey(context.Background(), "software:signing:rsa:kid-rotate-exportable--v2", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err, "the rotated key must still be exportable")
	assert.NotEmpty(t, wrapped.WrappedKey)
}

func TestRotateKeyByKID_UnknownKID_NotFound(t *testing.T) {
	setupRealSoftwareKID(t)

	_, err := RotateKey(context.Background(), "software:::does-not-exist")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ------------------------------------------------------------------------
// CopyKey
// ------------------------------------------------------------------------

// registerSecondSoftwareBackend registers a second, independent in-memory
// software backend under name, so CopyKey has a genuine cross-backend
// destination.
func registerSecondSoftwareBackend(t *testing.T, name string) {
	t.Helper()
	softwareBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	b, err := New(&BackendConfig{Backend: softwareBackend, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, RegisterServiceBackend(name, b))
}

// generateKIDTestECDSAKey generates a P-256 ECDSA signing key named cn on the
// registered "software" backend, with Exportable set as given. CopyKey's
// package-level wrapping algorithm is hardcoded to plain RSAES-OAEP-SHA256
// (unrelated to #925 -- see CopyKey in service.go), whose maximum payload is
// smaller than an RSA-2048 private key's PKCS#8 DER; an EC P-256 key's DER is
// well under that limit, so the success path here actually exercises the
// wrap-and-import round trip instead of failing on an unrelated size limit.
func generateKIDTestECDSAKey(t *testing.T, cn string, exportable bool) {
	t.Helper()
	b, err := GetBackend("software")
	require.NoError(t, err)

	_, err = b.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		Exportable:    exportable,
	})
	require.NoError(t, err)
}

// TestCopyKeyByKID_ExportableTrue_Succeeds proves CopyKey's source-side
// export -- ExportKeyTo, gated on the same Exportable field as ExportKey --
// also uses the source backend's stored attrs rather than sourceKID's
// reconstruction (#925).
func TestCopyKeyByKID_ExportableTrue_Succeeds(t *testing.T) {
	setupRealSoftwareKID(t)
	generateKIDTestECDSAKey(t, "kid-copy-true", true)
	registerSecondSoftwareBackend(t, "software2")

	err := CopyKey(context.Background(), "software:signing:ecdsa-p256:kid-copy-true", "software2", nil)
	require.NoError(t, err)

	destB, err := GetBackend("software2")
	require.NoError(t, err)
	_, err = destB.GetKey(context.Background(), &types.KeyAttributes{
		CN:            "kid-copy-true",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	assert.NoError(t, err, "the copy must be readable from the destination backend")
}

func TestCopyKeyByKID_ExportableFalse_Refused(t *testing.T) {
	setupRealSoftwareKID(t)
	generateKIDTestRSAKey(t, "kid-copy-false", false)
	registerSecondSoftwareBackend(t, "software2")

	err := CopyKey(context.Background(), "software:signing:rsa:kid-copy-false", "software2", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
}

func TestCopyKeyByKID_UnknownSourceKID_NotFound(t *testing.T) {
	setupRealSoftwareKID(t)
	registerSecondSoftwareBackend(t, "software2")

	err := CopyKey(context.Background(), "software:::does-not-exist", "software2", nil)
	require.Error(t, err)
	var copyErr *ErrCopyKeyBackend
	require.True(t, errors.As(err, &copyErr))
	assert.Equal(t, "source", copyErr.Role)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}
