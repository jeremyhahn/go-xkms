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

package pkcs8

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ============================================================================
// Coverage-gap tests for sealer.go: real behavior + error paths not
// exercised elsewhere.
// ============================================================================

// x25519SealAttrs returns key attributes for an X25519 key agreement key.
// X25519 keys are valid PKCS8Backend keys but are not one of the types
// deriveSealingKey knows how to extract scalar material from (RSA, ECDSA,
// Ed25519), so they exercise deriveSealingKey's "unsupported key type"
// branch through the public Seal/Unseal API.
func x25519SealAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:               cn,
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
	}
}

// TestSeal_UnsupportedKeyTypeForSealing verifies that Seal wraps
// deriveSealingKey's "unsupported key type" error when asked to seal with
// an X25519 key (valid for key agreement, not for HKDF scalar-based
// sealing).
func TestSeal_UnsupportedKeyTypeForSealing(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := x25519SealAttrs("seal-x25519-unsupported.com")
	if _, ok := requireX25519Key(t, be, attrs); !ok {
		return
	}

	_, err := be.Seal(context.Background(), []byte("secret data"), &types.SealOptions{KeyAttributes: attrs})
	if err == nil {
		t.Fatal("Seal should fail for a key type deriveSealingKey does not support")
	}
	if !strings.Contains(err.Error(), "failed to derive sealing key") {
		t.Errorf("expected 'failed to derive sealing key' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported key type for sealing") {
		t.Errorf("expected underlying 'unsupported key type for sealing' cause, got: %v", err)
	}
}

// TestUnseal_LoadSealingKeyError verifies that Unseal wraps GetKey's
// failure when the referenced key does not exist.
func TestUnseal_LoadSealingKeyError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("unseal-missing-key.com", 2048)
	sealed := &types.SealedData{
		Backend: types.BackendTypeSoftware,
		KeyID:   attrs.KeyID(),
		Nonce:   make([]byte, 12),
	}

	_, err := be.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs})
	if err == nil {
		t.Fatal("Unseal should fail when the sealing key does not exist")
	}
	if !strings.Contains(err.Error(), "failed to load sealing key") {
		t.Errorf("expected 'failed to load sealing key' error, got: %v", err)
	}
}

// TestUnseal_UnsupportedKeyTypeForSealing verifies that Unseal reaches
// deriveSealingKey's "unsupported key type" branch for an X25519 key. The
// sealed envelope's ciphertext/tag content is irrelevant since the error
// occurs before decryption is attempted.
func TestUnseal_UnsupportedKeyTypeForSealing(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := x25519SealAttrs("unseal-x25519-unsupported.com")
	if _, ok := requireX25519Key(t, be, attrs); !ok {
		return
	}

	sealed := &types.SealedData{
		Backend: types.BackendTypeSoftware,
		KeyID:   attrs.KeyID(),
		Nonce:   make([]byte, 12),
	}

	_, err := be.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs})
	if err == nil {
		t.Fatal("Unseal should fail for a key type deriveSealingKey does not support")
	}
	if !strings.Contains(err.Error(), "failed to derive sealing key") {
		t.Errorf("expected 'failed to derive sealing key' error, got: %v", err)
	}
}

// TestUnseal_InvalidNonceSize verifies that Unseal rejects a sealed
// envelope whose nonce length does not match the AES-GCM nonce size for
// the derived sealing key.
func TestUnseal_InvalidNonceSize(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("unseal-bad-nonce.com", 2048)
	if _, err := be.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		KeyID:      attrs.KeyID(),
		Nonce:      make([]byte, 4), // AES-GCM standard nonce is 12 bytes
		Ciphertext: []byte("irrelevant"),
		Tag:        make([]byte, 16),
	}

	_, err := be.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs})
	if err == nil {
		t.Fatal("Unseal should fail for a mismatched nonce size")
	}
	if !strings.Contains(err.Error(), "invalid nonce size") {
		t.Errorf("expected 'invalid nonce size' error, got: %v", err)
	}
}

// TestUnseal_NilOptions verifies the nil-options guard.
func TestUnsealNilOptionsGap(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	sealed := &types.SealedData{Backend: types.BackendTypeSoftware}
	_, err := be.Unseal(context.Background(), sealed, nil)
	if err == nil {
		t.Fatal("Unseal should fail with nil options")
	}
}

// TestUnseal_NilKeyAttributes verifies the nil KeyAttributes guard.
func TestUnsealNilKeyAttributesGap(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	sealed := &types.SealedData{Backend: types.BackendTypeSoftware}
	_, err := be.Unseal(context.Background(), sealed, &types.UnsealOptions{})
	if err == nil {
		t.Fatal("Unseal should fail with nil KeyAttributes")
	}
}
