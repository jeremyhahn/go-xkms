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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/importtoken"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// go-xkms#1261: this backend's importTokens map previously grew without
// bound -- one entry per CN GetImportParameters was ever called for, never
// swept for expiry, never capped, and (unlike the other backends fixed
// alongside it) never even cleared on Close.

// TestGetImportParameters_CapEnforced verifies the hard cap holds: once
// the import-token store is full, GetImportParameters reports a typed
// *importtoken.LimitExceededError instead of growing past the limit.
func TestGetImportParameters_CapEnforced(t *testing.T) {
	b, _ := testBackend(t)
	b.importTokens = importtoken.New[*importtoken.SealedRSAKey](time.Hour, 2, (*importtoken.SealedRSAKey).Destroy)

	for i := 0; i < 2; i++ {
		attrs := &types.KeyAttributes{
			CN:           "cap-" + string(rune('a'+i)),
			KeyAlgorithm: x509.RSA,
		}
		if _, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); err != nil {
			t.Fatalf("GetImportParameters() call %d unexpected error = %v", i, err)
		}
	}

	_, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN:           "cap-overflow",
		KeyAlgorithm: x509.RSA,
	}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err == nil {
		t.Fatal("GetImportParameters() expected an error once the store is at capacity")
	}
	var limitErr *importtoken.LimitExceededError
	if !errors.As(err, &limitErr) {
		t.Fatalf("expected *importtoken.LimitExceededError, got %T: %v", err, err)
	}
	if limitErr.Limit != 2 {
		t.Errorf("LimitExceededError.Limit = %d, want 2", limitErr.Limit)
	}
	if got := b.importTokens.Len(); got != 2 {
		t.Errorf("importTokens.Len() = %d, want 2 (the cap must hold)", got)
	}
}

// TestGetImportParameters_ExpiredTokenSwept verifies an expired token is
// swept: a Store with a very short TTL loses its entry by the time a
// second Put runs the sweep.
func TestGetImportParameters_ExpiredTokenSwept(t *testing.T) {
	b, _ := testBackend(t)
	b.importTokens = importtoken.New[*importtoken.SealedRSAKey](time.Nanosecond, importtoken.DefaultMaxTokens, (*importtoken.SealedRSAKey).Destroy)

	attrs := &types.KeyAttributes{CN: "expiring", KeyAlgorithm: x509.RSA}
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() unexpected error = %v", err)
	}

	time.Sleep(time.Millisecond)

	if _, err := b.importTokens.Peek(string(params.ImportToken)); err == nil {
		t.Error("expired import token should have been swept")
	}
}

// TestImportTokens_EvictionDestroysWrappingKey verifies eviction destroys
// the sealed wrapping key: the Store's destroy callback
// ((*importtoken.SealedRSAKey).Destroy) is wired in for production use, so
// a deleted entry's enclave can no longer be opened.
func TestImportTokens_EvictionDestroysWrappingKey(t *testing.T) {
	b, _ := testBackend(t)

	sealed := newTestSealedRSAKey(t)
	if _, err := b.importTokens.Put("evict-me", sealed); err != nil {
		t.Fatalf("Put() unexpected error = %v", err)
	}

	b.importTokens.Delete("evict-me")

	err := sealed.Use(func(*rsa.PrivateKey) error { return nil })
	var unavailable *importtoken.UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Use() after Delete: expected *importtoken.UnavailableError, got %T: %v", err, err)
	}
}
