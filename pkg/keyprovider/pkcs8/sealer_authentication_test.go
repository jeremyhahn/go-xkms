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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var pkcs8SealAuthAAD = []byte("tenant=acme,purpose=barrier")

// ecdsaSealingKey generates a P-256 key the backend can seal under.
func ecdsaSealingKey(t *testing.T, be *PKCS8Backend, cn string) *types.KeyAttributes {
	t.Helper()
	curve, err := types.ParseCurve("P-256")
	if err != nil {
		t.Fatalf("ParseCurve: %v", err)
	}
	attrs := &types.KeyAttributes{
		CN:            cn,
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_SW,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: curve},
		Hash:          crypto.SHA256,
	}
	if _, err := be.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey(%s): %v", cn, err)
	}
	return attrs
}

func cloneSealedData(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Nonce = bytes.Clone(sealed.Nonce)
	c.Tag = bytes.Clone(sealed.Tag)
	return &c
}

// TestUnseal_SealedDataAuthentication proves every way the sealed data itself
// can be wrong is reported as types.ErrSealedDataAuthentication.
func TestUnseal_SealedDataAuthentication(t *testing.T) {
	be, _ := createTestBackend(t)
	t.Cleanup(func() {
		if err := be.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	keyA := ecdsaSealingKey(t, be, "seal-auth-a")
	keyB := ecdsaSealingKey(t, be, "seal-auth-b")
	ctx := context.Background()

	sealed, err := be.Seal(ctx, []byte("software sealed root key"), &types.SealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(s *types.SealedData) *types.UnsealOptions
	}{
		{"ciphertext bit flipped", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"tag bit flipped", func(s *types.SealedData) *types.UnsealOptions {
			s.Tag[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"nonce bit flipped", func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"truncated", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"extended", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"AAD mismatch", func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: []byte("tenant=evil")}
		}},
		{"AAD omitted", func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyA}
		}},
		{"foreign key named by sealed KeyID", func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: keyB, AAD: pkcs8SealAuthAAD}
		}},
		{"foreign key detected by AES-GCM", func(s *types.SealedData) *types.UnsealOptions {
			s.KeyID = ""
			return &types.UnsealOptions{KeyAttributes: keyB, AAD: pkcs8SealAuthAAD}
		}},
		{"wrong backend", func(s *types.SealedData) *types.UnsealOptions {
			s.Backend = types.BackendTypePKCS11
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"malformed: nonce missing", func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce = nil
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"malformed: tag short", func(s *types.SealedData) *types.UnsealOptions {
			s.Tag = s.Tag[:8]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
		{"malformed: tag bytes moved into ciphertext", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, s.Tag[0])
			s.Tag = s.Tag[1:]
			return &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneSealedData(sealed)
			opts := tc.mutate(mutated)

			out, err := be.Unseal(ctx, mutated, opts)
			if out != nil {
				t.Fatalf("Unseal returned plaintext %q for bad sealed data", out)
			}
			if !errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("Unseal error %v does not match ErrSealedDataAuthentication", err)
			}
		})
	}

	got, err := be.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: keyA, AAD: pkcs8SealAuthAAD})
	if err != nil {
		t.Fatalf("the untouched envelope must still unseal: %v", err)
	}
	if !bytes.Equal(got, []byte("software sealed root key")) {
		t.Fatalf("Unseal = %q", got)
	}
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication proves a cancelled
// context, a closed backend and a sealing key that cannot be loaded are never
// reported as sealed-data authentication failures, even when the sealed data
// handed in would itself fail authentication.
func TestUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	t.Run("cancelled context with tampered data", func(t *testing.T) {
		be, _ := createTestBackend(t)
		t.Cleanup(func() { _ = be.Close() }) // best-effort: the assertions above already ran
		key := ecdsaSealingKey(t, be, "seal-env-ctx")
		sealed, err := be.Seal(context.Background(), []byte("x"), &types.SealOptions{KeyAttributes: key})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		sealed.Ciphertext = append(sealed.Ciphertext, 0x00)
		sealed.Backend = types.BackendTypeVault

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = be.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: key})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Unseal error %v, want context.Canceled", err)
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatal("a cancelled context must not be reported as sealed-data authentication")
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		be, _ := createTestBackend(t)
		key := ecdsaSealingKey(t, be, "seal-env-closed")
		sealed, err := be.Seal(context.Background(), []byte("x"), &types.SealOptions{KeyAttributes: key})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if err := be.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		sealed.Tag[0] ^= 0x01

		_, err = be.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: key})
		if !errors.Is(err, ErrStorageClosed) {
			t.Fatalf("Unseal error %v, want ErrStorageClosed", err)
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatal("a closed backend must not be reported as sealed-data authentication")
		}
	})

	t.Run("sealing key missing", func(t *testing.T) {
		be, _ := createTestBackend(t)
		t.Cleanup(func() { _ = be.Close() }) // best-effort: the assertions above already ran
		key := ecdsaSealingKey(t, be, "seal-env-missing")
		sealed, err := be.Seal(context.Background(), []byte("x"), &types.SealOptions{KeyAttributes: key})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if err := be.DeleteKey(context.Background(), key); err != nil {
			t.Fatalf("DeleteKey: %v", err)
		}

		_, err = be.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: key})
		if err == nil {
			t.Fatal("Unseal must fail without the sealing key")
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatalf("a missing key %v reported as sealed-data authentication", err)
		}
	})
}
