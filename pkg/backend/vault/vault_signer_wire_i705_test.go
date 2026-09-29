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
	"crypto"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newVaultSignerBackend builds a bare *Backend pointed at addr, with no
// generated key and no double -- these tests construct a *vaultSigner
// directly, so they need only a client wired to addr, not a well-behaved
// Transit stand-in.
func newVaultSignerBackend(t *testing.T, addr string) *Backend {
	t.Helper()
	b, err := NewBackend(&Config{
		Address:     addr,
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestVaultSigner_Sign_InvalidKeyVersion proves Sign rejects a Signer whose
// pinned version string isn't a valid integer before making any Vault call
// (go-xkms#705): version is normally set by Signer() from a real Vault
// response, but a corrupted in-memory value must still fail safely rather
// than being sent to Vault as a malformed request.
func TestVaultSigner_Sign_InvalidKeyVersion(t *testing.T) {
	b := newVaultSignerBackend(t, "http://unreachable.invalid")
	s := &vaultSigner{
		backend: b,
		attrs:   &types.KeyAttributes{CN: "sign-bad-version", KeyAlgorithm: x509.RSA},
		version: "not-a-number",
	}
	if _, err := s.Sign(nil, []byte("digest"), crypto.SHA256); err == nil {
		t.Error("Sign() expected error for a non-numeric key version, got nil")
	}
}

// TestVaultSigner_Sign_UnsupportedHash proves Sign surfaces
// getHashAlgorithm's rejection of a hash it doesn't map to a Vault
// algorithm name, for every non-Ed25519 key (which alone skips
// getHashAlgorithm).
func TestVaultSigner_Sign_UnsupportedHash(t *testing.T) {
	b := newVaultSignerBackend(t, "http://unreachable.invalid")
	s := &vaultSigner{
		backend: b,
		attrs:   &types.KeyAttributes{CN: "sign-bad-hash", KeyAlgorithm: x509.RSA, Hash: crypto.MD5},
		version: "1",
	}
	if _, err := s.Sign(nil, []byte("digest"), crypto.MD5); err == nil {
		t.Error("Sign() expected error for an unsupported hash algorithm, got nil")
	}
}

// TestVaultSigner_Sign_TransitError proves Sign surfaces a Transit sign RPC
// failure wrapped, rather than a zero-length signature.
func TestVaultSigner_Sign_TransitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVaultError(w, http.StatusForbidden, "permission denied")
	}))
	t.Cleanup(server.Close)

	b := newVaultSignerBackend(t, server.URL)
	s := &vaultSigner{
		backend: b,
		attrs:   &types.KeyAttributes{CN: "sign-transit-error", KeyAlgorithm: x509.RSA},
		version: "1",
	}
	if _, err := s.Sign(nil, []byte("digest"), crypto.SHA256); err == nil {
		t.Error("Sign() expected error when the Transit sign RPC fails, got nil")
	}
}

// TestVaultSigner_Sign_MalformedResponses drives Sign against a series of
// Transit "sign" responses that are well-formed JSON but missing or
// misshapen in exactly the ways Sign's own response-parsing guards check
// for, proving each guard rejects the response rather than panicking or
// returning a garbage signature.
func TestVaultSigner_Sign_MalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "no signature field",
			data: map[string]interface{}{},
		},
		{
			name: "signature field wrong type",
			data: map[string]interface{}{"signature": 12345},
		},
		{
			name: "signature missing vault:vN: prefix",
			data: map[string]interface{}{"signature": "not-the-right-format"},
		},
		{
			name: "signature base64 payload invalid",
			data: map[string]interface{}{"signature": "vault:v1:not-valid-base64!!"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := newMalformedTransitKeyServer(t, tt.data)
			b := newVaultSignerBackend(t, addr)
			s := &vaultSigner{
				backend: b,
				attrs:   &types.KeyAttributes{CN: "sign-malformed-" + tt.name, KeyAlgorithm: x509.RSA},
				version: "1",
			}
			if _, err := s.Sign(nil, []byte("digest"), crypto.SHA256); err == nil {
				t.Errorf("Sign() expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestVaultSigner_Sign_Ed25519_TransitError proves the Ed25519 branch of
// Sign (which skips getHashAlgorithm and builds a different request shape)
// also surfaces a Transit RPC failure wrapped, rather than only the
// RSA/ECDSA branch tested above.
func TestVaultSigner_Sign_Ed25519_TransitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVaultError(w, http.StatusForbidden, "permission denied")
	}))
	t.Cleanup(server.Close)

	b := newVaultSignerBackend(t, server.URL)
	s := &vaultSigner{
		backend: b,
		attrs:   &types.KeyAttributes{CN: "sign-ed25519-transit-error", KeyAlgorithm: x509.Ed25519},
		version: "1",
	}
	if _, err := s.Sign(nil, []byte("digest"), crypto.Hash(0)); err == nil {
		t.Error("Sign() expected error when the Transit sign RPC fails (Ed25519 branch), got nil")
	}
}
