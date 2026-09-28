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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests cover the process-singleton free functions WrapKeyByID and
// UnwrapKeyByID (service.go), added beside ExportKey/WrapKey/UnwrapKey/
// GetImportParameters as the in-process entry points the embedded PKCS#11
// transport (xkey/pkg/pkcs11) drives instead of the broken key-IMPORT
// ceremony it used to route C_WrapKey/C_UnwrapKey through (go-xkms#1195).
// The wrap/unwrap mechanics themselves -- AES-KW, RSA-OAEP, the legacy
// mechanisms, the oracle-safety properties -- are exercised in depth against
// XKMSService.WrapKeyByID/UnwrapKeyByID directly by
// servicer_wrapkey_*_test.go; these tests only prove the free functions
// delegate to the singleton and surface ErrNotInitialized the same way
// GetBackend's siblings do.

// generateTestSymmetricKey generates an exportable AES-256 key in the
// "software" backend via the GenerateSymmetricKey free function
// (service.go), and returns its attributes.
func generateTestSymmetricKey(t *testing.T, cn string) *types.KeyAttributes {
	t.Helper()

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.StoreSoftware,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}
	_, err := GenerateSymmetricKey(context.Background(), "software", attrs)
	require.NoError(t, err)
	return attrs
}

// TestWrapKeyByID_FreeFunction_Success proves the free function delegates to
// the initialized singleton's WrapKeyByID and returns a wrapped blob that is
// not the plaintext key material. The wrap/unwrap mechanics are exercised in
// depth against XKMSService.WrapKeyByID directly by
// TestWrapKeyByID_Success in servicer_keyops_test.go; this only proves the
// free function reaches it.
func TestWrapKeyByID_FreeFunction_Success(t *testing.T) {
	setupDeriveService(t)
	ctx := context.Background()

	wrappingKey := generateTestSymmetricKey(t, "wrap-by-id-kek")
	targetKey := generateTestSymmetricKey(t, "wrap-by-id-target")

	resp, err := WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software", WrappingKeyID: wrappingKey.CN,
		TargetKeyBackend: "software", TargetKeyID: targetKey.CN,
		Algorithm: string(types.WrapAESKW),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.WrappedKey)
	assert.Equal(t, string(types.WrapAESKW), resp.Algorithm)
}

// TestWrapKeyByID_FreeFunction_NotInitialized proves the free function
// reports ErrNotInitialized -- the same typed sentinel GetBackend and its
// siblings return -- rather than panicking or wrapping a nil-pointer fault,
// when called before Initialize.
func TestWrapKeyByID_FreeFunction_NotInitialized(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	_, err := WrapKeyByID(context.Background(), &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software", WrappingKeyID: "kek",
		TargetKeyBackend: "software", TargetKeyID: "target",
		Algorithm: string(types.WrapAESKW),
	})
	assert.True(t, errors.Is(err, ErrNotInitialized), "got %v, want ErrNotInitialized", err)
}

// TestUnwrapKeyByID_FreeFunction_Success proves the free function delegates
// to the initialized singleton's UnwrapKeyByID: a key wrapped through
// WrapKeyByID is recovered and imported as a new resident key holding the
// identical material. The unwrap mechanics are exercised in depth against
// XKMSService.UnwrapKeyByID directly by TestUnwrapKeyByID_Success in
// servicer_keyops_test.go; this only proves the free function reaches it.
func TestUnwrapKeyByID_FreeFunction_Success(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	wrappingKey := generateTestSymmetricKey(t, "unwrap-by-id-kek")
	targetKey := generateTestSymmetricKey(t, "unwrap-by-id-target")

	wrapResp, err := WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software", WrappingKeyID: wrappingKey.CN,
		TargetKeyBackend: "software", TargetKeyID: targetKey.CN,
		Algorithm: string(types.WrapAESKW),
	})
	require.NoError(t, err)

	const unwrappedKeyID = "unwrap-by-id-recovered"
	unwrapResp, err := UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapResp.WrappedKey,
		UnwrappingKeyBackend: "software", UnwrappingKeyID: wrappingKey.CN,
		Algorithm:        string(types.WrapAESKW),
		TargetKeyBackend: "software", TargetKeyID: unwrappedKeyID,
		TargetKeyType: "AES", TargetExportable: true,
	})
	require.NoError(t, err)
	assert.True(t, unwrapResp.Success)
	assert.Equal(t, unwrappedKeyID, unwrapResp.KeyID)

	want := rawSymmetricMaterial(t, svc, targetKey)
	got := rawSymmetricMaterial(t, svc, &types.KeyAttributes{
		CN: unwrappedKeyID, StoreType: types.StoreSoftware, KeyType: types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	assert.Equal(t, want, got, "the unwrapped key must hold the same material as the original")
}

// TestUnwrapKeyByID_FreeFunction_NotInitialized proves the free function
// reports ErrNotInitialized before Initialize has run.
func TestUnwrapKeyByID_FreeFunction_NotInitialized(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	_, err := UnwrapKeyByID(context.Background(), &transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("opaque"),
		UnwrappingKeyBackend: "software", UnwrappingKeyID: "kek",
		Algorithm:        string(types.WrapAESKW),
		TargetKeyBackend: "software", TargetKeyID: "target",
		TargetKeyType: "AES",
	})
	assert.True(t, errors.Is(err, ErrNotInitialized), "got %v, want ErrNotInitialized", err)
}
