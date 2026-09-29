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

//go:build azurekv

package azurekv

import (
	"bytes"
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestSeal_Unseal_RoundTrip proves the full success path (go-xkms#705): every
// existing sealer_test.go/sealer_gaps_test.go case is a rejected-input or
// SymmetricEncrypter-failure path, so Seal and Unseal's own AES-GCM
// encrypt/decrypt calls, sealed.Metadata construction, and the
// metadata-driven algorithm/AAD reconstruction on the way back in had never
// run. This drives Seal then Unseal through a real symmetric key generated
// via testBackendWithSecrets (the same Secrets API seam
// TestGenerateSymmetricKey_StoresSecretAndRoundTrips uses), so both
// directions exercise the real SymmetricEncrypter, not a stub.
func TestSeal_Unseal_RoundTrip(t *testing.T) {
	b, _ := testBackendWithSecrets(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "seal-roundtrip-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	sealed, err := b.Seal(context.Background(), plaintext, &types.SealOptions{KeyAttributes: attrs})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if sealed.Backend != types.BackendTypeAzureKV {
		t.Errorf("sealed.Backend = %v, want %v", sealed.Backend, types.BackendTypeAzureKV)
	}
	if sealed.KeyID != attrs.ID() {
		t.Errorf("sealed.KeyID = %q, want %q", sealed.KeyID, attrs.ID())
	}
	if alg, ok := sealed.Metadata["azurekv:algorithm"]; !ok || len(alg) == 0 {
		t.Error("sealed.Metadata[\"azurekv:algorithm\"] must be set by Seal")
	}
	if bytes.Equal(sealed.Ciphertext, plaintext) {
		t.Error("Seal must not return the plaintext unchanged as ciphertext")
	}

	recovered, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs})
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("Unseal() = %q, want %q", recovered, plaintext)
	}
}

// TestSeal_Unseal_RoundTrip_WithAAD mirrors TestSeal_Unseal_RoundTrip with
// additional authenticated data, proving Seal's "azurekv:has_aad" metadata
// branch is set and that Unseal's AAD threading through DecryptOptions
// actually binds -- both a wrong AAD and a missing AAD on unseal must fail
// authentication, not silently succeed.
func TestSeal_Unseal_RoundTrip_WithAAD(t *testing.T) {
	b, _ := testBackendWithSecrets(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "seal-roundtrip-aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	plaintext := []byte("aad-bound secret")
	aad := []byte("context-binding-value")

	sealed, err := b.Seal(context.Background(), plaintext, &types.SealOptions{KeyAttributes: attrs, AAD: aad})
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if v, ok := sealed.Metadata["azurekv:has_aad"]; !ok || string(v) != "true" {
		t.Error(`sealed.Metadata["azurekv:has_aad"] must be "true" when AAD is provided`)
	}

	t.Run("correct AAD unseals", func(t *testing.T) {
		recovered, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs, AAD: aad})
		if err != nil {
			t.Fatalf("Unseal with matching AAD failed: %v", err)
		}
		if !bytes.Equal(recovered, plaintext) {
			t.Errorf("Unseal() = %q, want %q", recovered, plaintext)
		}
	})

	t.Run("wrong AAD fails authentication", func(t *testing.T) {
		if _, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs, AAD: []byte("wrong")}); err == nil {
			t.Error("Unseal with mismatched AAD must fail authentication, got nil error")
		}
	})

	t.Run("missing AAD fails authentication", func(t *testing.T) {
		if _, err := b.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: attrs}); err == nil {
			t.Error("Unseal without AAD must fail authentication when Seal used AAD, got nil error")
		}
	})
}
