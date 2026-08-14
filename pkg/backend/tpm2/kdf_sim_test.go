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

//go:build tpm_simulator

package tpm2

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func simKDFParams(salt, info []byte, length int) *kdf.KDFParams {
	return &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      salt,
		Info:      info,
		KeyLength: length,
	}
}

// TestDeriveFromSymmetricKey_OverRealSealedKeys drives the backend's
// derivation against a real (simulated) TPM.
//
// The byte-exact oracle lives one layer down, in
// pkg/tpm2/symmetric_kdf_sim_test.go, where the test is in the same package as
// TPM2_Unseal and can name the material the KDF must run over. What this test
// adds is that the backend's own entry point reaches that derivation with the
// caller's parameters intact, over the key the caller named.
//
// go-tpm-tools' simulator is a process-wide singleton, so a single backend
// serves the whole test.
func TestDeriveFromSymmetricKey_OverRealSealedKeys(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()

	newSealedKey := func(cn string) *types.KeyAttributes {
		attrs := &types.KeyAttributes{
			CN:                 cn,
			StoreType:          types.StoreTPM2,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		if _, err := b.GenerateSymmetricKey(ctx, attrs); err != nil {
			t.Fatalf("GenerateSymmetricKey(%s): %v", cn, err)
		}
		return attrs
	}

	first := newSealedKey("kdf-sealed-one")
	second := newSealedKey("kdf-sealed-two")

	salt := []byte("go-xkms/tpm2/salt")
	info := []byte("go-xkms/tpm2/info")

	derive := func(t *testing.T, attrs *types.KeyAttributes, params *kdf.KDFParams) []byte {
		t.Helper()
		out, err := b.DeriveFromSymmetricKey(ctx, attrs, params)
		if err != nil {
			t.Fatalf("DeriveFromSymmetricKey(%s): %v", attrs.CN, err)
		}
		if len(out) != params.KeyLength {
			t.Fatalf("derived %d bytes, want %d", len(out), params.KeyLength)
		}
		return out
	}

	firstDerived := derive(t, first, simKDFParams(salt, info, 32))
	secondDerived := derive(t, second, simKDFParams(salt, info, 32))

	// The regression assertion: identical salt and info, two different sealed
	// base keys, two different derived keys. Under the code this replaced both
	// derivations ran over the key's identifier string.
	if bytes.Equal(firstDerived, secondDerived) {
		t.Fatal("two different sealed base keys derived the same bytes under identical salt and info")
	}

	t.Run("deterministic for one key", func(t *testing.T) {
		again := derive(t, first, simKDFParams(salt, info, 32))
		if !bytes.Equal(firstDerived, again) {
			t.Fatal("the same sealed key and parameters derived two different keys; a derivation " +
				"an application cannot repeat is not a key derivation")
		}
	})

	t.Run("salt only", func(t *testing.T) {
		if bytes.Equal(firstDerived, derive(t, first, simKDFParams([]byte("another-salt"), info, 32))) {
			t.Fatal("changing only the salt produced the same key")
		}
	})

	t.Run("info only", func(t *testing.T) {
		if bytes.Equal(firstDerived, derive(t, first, simKDFParams(salt, []byte("another-info"), 32))) {
			t.Fatal("changing only the info produced the same key")
		}
	})

	t.Run("the sealed key still refuses to be exported", func(t *testing.T) {
		// Deriving must not have turned the TPM into an export path: the
		// backend releases derived bytes and nothing else.
		if _, err := b.ExportKeyMaterial(ctx, first); err == nil {
			t.Fatal("ExportKeyMaterial succeeded on a TPM-sealed key")
		}
	})

	t.Run("a key that does not exist", func(t *testing.T) {
		missing := &types.KeyAttributes{
			CN:                 "kdf-no-such-sealed-key",
			StoreType:          types.StoreTPM2,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		if _, err := b.DeriveFromSymmetricKey(ctx, missing, simKDFParams(salt, info, 32)); err == nil {
			t.Fatal("deriving from a key that does not exist succeeded")
		}
	})
}
