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

//go:build vault

package vault

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSeal_ValidationErrors proves Seal's guards: nil opts, nil
// KeyAttributes, and an asymmetric key, none of which should reach Vault.
func TestSeal_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	if _, err := b.Seal(context.Background(), []byte("data"), nil); err == nil {
		t.Error("Seal(nil opts) expected error, got nil")
	}
	if _, err := b.Seal(context.Background(), []byte("data"), &types.SealOptions{}); err == nil {
		t.Error("Seal(nil KeyAttributes) expected error, got nil")
	}
	asymmetric := &types.SealOptions{KeyAttributes: &types.KeyAttributes{
		CN:           "seal-asymmetric",
		KeyAlgorithm: x509.RSA,
	}}
	if _, err := b.Seal(context.Background(), []byte("data"), asymmetric); err == nil {
		t.Error("Seal(asymmetric key) expected error, got nil")
	}
}

// TestUnseal_ValidationErrors proves Unseal's guards: nil sealed data, the
// wrong originating backend, nil options, a key ID mismatch, and an
// asymmetric key, none of which should reach Vault.
func TestUnseal_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	symmetricAttrs := &types.KeyAttributes{
		CN:                 "unseal-validation-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	if _, err := b.Unseal(context.Background(), nil, &types.UnsealOptions{KeyAttributes: symmetricAttrs}); err == nil {
		t.Error("Unseal(nil sealed) expected error, got nil")
	}

	if _, err := b.Unseal(context.Background(), &types.SealedData{Backend: "not-vault"}, &types.UnsealOptions{KeyAttributes: symmetricAttrs}); err == nil {
		t.Error("Unseal(wrong backend) expected error, got nil")
	}

	if _, err := b.Unseal(context.Background(), &types.SealedData{Backend: BackendTypeVault}, nil); err == nil {
		t.Error("Unseal(nil opts) expected error, got nil")
	}

	if _, err := b.Unseal(context.Background(), &types.SealedData{Backend: BackendTypeVault}, &types.UnsealOptions{}); err == nil {
		t.Error("Unseal(nil KeyAttributes) expected error, got nil")
	}

	mismatched := &types.SealedData{Backend: BackendTypeVault, KeyID: "some-other-key-id"}
	if _, err := b.Unseal(context.Background(), mismatched, &types.UnsealOptions{KeyAttributes: symmetricAttrs}); err == nil {
		t.Error("Unseal(key ID mismatch) expected error, got nil")
	}

	asymmetricAttrs := &types.KeyAttributes{CN: "unseal-asymmetric", KeyAlgorithm: x509.RSA}
	if _, err := b.Unseal(context.Background(), &types.SealedData{Backend: BackendTypeVault}, &types.UnsealOptions{KeyAttributes: asymmetricAttrs}); err == nil {
		t.Error("Unseal(asymmetric key) expected error, got nil")
	}
}

// TestUnmarshalSealedData_InvalidJSON proves UnmarshalSealedData surfaces a
// JSON decode failure rather than returning a zero-value SealedData.
func TestUnmarshalSealedData_InvalidJSON(t *testing.T) {
	if _, err := UnmarshalSealedData([]byte("not json")); err == nil {
		t.Error("UnmarshalSealedData() expected error for invalid JSON, got nil")
	}
}
