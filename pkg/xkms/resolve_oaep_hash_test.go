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

package xkms

import (
	"crypto"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestResolveOAEPHash_RefusesCollisionBrokenDigests is the transport-divergence
// regression test.
//
// The REST handler carried its own OAEP hash switch that accepted SHA-1 and
// encrypted with it, while gRPC and the service layer refused the same request.
// The digest a caller got therefore depended on which port the request arrived
// on, and the REST path returned HTTP 200 while using a collision-broken hash.
// Both transports now resolve here.
func TestResolveOAEPHash_RefusesCollisionBrokenDigests(t *testing.T) {
	// Every spelling the transports have ever accepted, including the bare
	// digest-size forms REST used to normalize itself.
	for _, name := range []string{"SHA-1", "SHA1", "sha1", "sha-1", "1", "MD5", "md5"} {
		h, err := ResolveOAEPHash(name)
		if err == nil {
			t.Errorf("ResolveOAEPHash(%q) = %v, want a refusal: OAEP must not use a "+
				"collision-broken digest", name, h)
			continue
		}
		if !errors.Is(err, ErrWeakOAEPHash) {
			t.Errorf("ResolveOAEPHash(%q) error = %v, want ErrWeakOAEPHash", name, err)
		}
		if h != 0 {
			t.Errorf("ResolveOAEPHash(%q) returned hash %v alongside its error", name, h)
		}
	}
}

// TestResolveOAEPHash_AcceptsStrongDigests is the accept side: the refusal must
// not be over-broad, and the bare digest-size spellings must still normalize.
func TestResolveOAEPHash_AcceptsStrongDigests(t *testing.T) {
	tests := map[string]crypto.Hash{
		"":         crypto.SHA256, // unset selects the documented default
		"SHA-256":  crypto.SHA256,
		"sha256":   crypto.SHA256,
		"256":      crypto.SHA256,
		"SHA-384":  crypto.SHA384,
		"384":      crypto.SHA384,
		"SHA-512":  crypto.SHA512,
		"512":      crypto.SHA512,
		"SHA3-256": crypto.SHA3_256,
	}

	for name, want := range tests {
		got, err := ResolveOAEPHash(name)
		if err != nil {
			t.Errorf("ResolveOAEPHash(%q) unexpected error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ResolveOAEPHash(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestResolveOAEPHash_RefusesUnknownName covers the third outcome: a name that
// is neither weak nor recognized must be an error, never a silent default. That
// silent-default behaviour is what made an unresolvable name encrypt under
// SHA-256 and report success.
func TestResolveOAEPHash_RefusesUnknownName(t *testing.T) {
	for _, name := range []string{"SHA-257", "not-a-hash", "sha", "0"} {
		h, err := ResolveOAEPHash(name)
		if err == nil {
			t.Errorf("ResolveOAEPHash(%q) = %v, want an error rather than a default", name, h)
		}
		if h != 0 {
			t.Errorf("ResolveOAEPHash(%q) returned hash %v alongside its error", name, h)
		}
	}
}

// TestResolveOAEPHash_IgnoresWeakHashPolicy pins the deliberate asymmetry with
// signing.
//
// crypto.allow_weak_hashes re-admits SHA-1 for signing and attestation, where
// legacy material has to stay readable. OAEP has no legacy ciphertexts in this
// codebase, so the escape hatch must not reach it: a SHA-1 OAEP request is
// refused even in a deployment that has opted into weak hashes elsewhere.
func TestResolveOAEPHash_IgnoresWeakHashPolicy(t *testing.T) {
	restore := types.AllowWeakHashes()
	types.SetAllowWeakHashes(true)
	t.Cleanup(func() { types.SetAllowWeakHashes(restore) })

	// Precondition: the policy really is on, so signing would accept SHA-1.
	if _, err := ResolveHash("SHA-1"); err != nil {
		t.Fatalf("precondition: with weak hashes allowed, ResolveHash(SHA-1) must succeed, got %v", err)
	}

	if h, err := ResolveOAEPHash("SHA-1"); !errors.Is(err, ErrWeakOAEPHash) {
		t.Errorf("ResolveOAEPHash(SHA-1) = (%v, %v) under allow_weak_hashes; "+
			"OAEP must refuse regardless of the signing policy", h, err)
	}
}
