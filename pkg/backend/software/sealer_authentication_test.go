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

package software

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

var softwareSealAuthAAD = []byte("tenant=acme,purpose=barrier")

// softwareSealFixture is a software backend with two sealing keys and one
// value sealed under the first.
type softwareSealFixture struct {
	backend *SoftwareBackend
	keyA    *types.KeyAttributes
	keyB    *types.KeyAttributes
	sealed  *types.SealedData
}

func newSoftwareSealFixture(t *testing.T) *softwareSealFixture {
	t.Helper()
	be, _ := createTestBackend(t)
	sb, ok := be.(*SoftwareBackend)
	if !ok {
		t.Fatalf("createTestBackend returned %T", be)
	}
	curve, err := types.ParseCurve("P-256")
	if err != nil {
		t.Fatalf("ParseCurve: %v", err)
	}
	key := func(cn string) *types.KeyAttributes {
		attrs := &types.KeyAttributes{
			CN:            cn,
			KeyType:       backend.KEY_TYPE_TLS,
			StoreType:     backend.STORE_SW,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{Curve: curve},
			Hash:          crypto.SHA256,
		}
		if _, err := sb.GenerateKey(context.Background(), attrs); err != nil {
			t.Fatalf("GenerateKey(%s): %v", cn, err)
		}
		return attrs
	}
	f := &softwareSealFixture{backend: sb, keyA: key("seal-auth-a"), keyB: key("seal-auth-b")}
	f.sealed, err = sb.Seal(context.Background(), []byte("software root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: softwareSealAuthAAD})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return f
}

func cloneSealedData(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Nonce = bytes.Clone(sealed.Nonce)
	c.Tag = bytes.Clone(sealed.Tag)
	return &c
}

// TestSoftwareUnseal_SealedDataAuthentication proves the software backend --
// which checks the backend type itself and delegates the open to PKCS8 --
// reports every way the sealed data can be wrong as
// types.ErrSealedDataAuthentication.
func TestSoftwareUnseal_SealedDataAuthentication(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions
	}{
		{"bit flipped", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: softwareSealAuthAAD}
		}},
		{"truncated", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: softwareSealAuthAAD}
		}},
		{"extended", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: softwareSealAuthAAD}
		}},
		{"AAD mismatch", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: []byte("tenant=evil")}
		}},
		{"foreign key", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			s.KeyID = ""
			return &types.UnsealOptions{KeyAttributes: f.keyB, AAD: softwareSealAuthAAD}
		}},
		{"wrong backend", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			s.Backend = types.BackendTypeAzureKV
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: softwareSealAuthAAD}
		}},
		{"malformed: nonce missing", func(f *softwareSealFixture, s *types.SealedData) *types.UnsealOptions {
			s.Nonce = nil
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: softwareSealAuthAAD}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSoftwareSealFixture(t)
			t.Cleanup(func() { _ = f.backend.Close() }) // best-effort: the assertions already ran
			mutated := cloneSealedData(f.sealed)
			opts := tc.mutate(f, mutated)

			out, err := f.backend.Unseal(context.Background(), mutated, opts)
			if out != nil {
				t.Fatalf("Unseal returned plaintext %q for bad sealed data", out)
			}
			if !errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("Unseal error %v does not match ErrSealedDataAuthentication", err)
			}
		})
	}
}

// TestSoftwareUnseal_EnvironmentFailuresAreNotAuthentication proves a closed
// backend and a cancelled context are not sealed-data authentication, even
// for sealed data that would fail it.
func TestSoftwareUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	t.Run("closed backend", func(t *testing.T) {
		f := newSoftwareSealFixture(t)
		if err := f.backend.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		tampered := cloneSealedData(f.sealed)
		tampered.Backend = types.BackendTypeVault

		_, err := f.backend.Unseal(context.Background(), tampered, &types.UnsealOptions{KeyAttributes: f.keyA})
		if !errors.Is(err, ErrStorageClosed) {
			t.Fatalf("Unseal error %v, want ErrStorageClosed", err)
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatal("a closed backend must not be reported as sealed-data authentication")
		}
	})

	t.Run("cancelled context with tampered data", func(t *testing.T) {
		f := newSoftwareSealFixture(t)
		t.Cleanup(func() { _ = f.backend.Close() }) // best-effort: the assertions already ran
		tampered := cloneSealedData(f.sealed)
		tampered.Backend = types.BackendTypeVault

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.backend.Unseal(ctx, tampered, &types.UnsealOptions{KeyAttributes: f.keyA})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Unseal error %v, want context.Canceled", err)
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatal("a cancelled context must not be reported as sealed-data authentication")
		}
	})
}
