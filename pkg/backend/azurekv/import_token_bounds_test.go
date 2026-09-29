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
	b.importTokens = importtoken.New[[]byte](time.Hour, 2, func([]byte) {})

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
	b.importTokens = importtoken.New[[]byte](time.Nanosecond, importtoken.DefaultMaxTokens, func([]byte) {})

	attrs := &types.KeyAttributes{CN: "expiring", KeyAlgorithm: x509.RSA}
	if _, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); err != nil {
		t.Fatalf("GetImportParameters() unexpected error = %v", err)
	}

	time.Sleep(time.Millisecond)

	if _, err := b.importTokens.Peek("import-token-expiring"); err == nil {
		t.Error("expired import token should have been swept")
	}
}

// TestImportTokens_EvictionZeroizesMaterial verifies eviction wipes the
// material: the Store's destroy callback (secure.Wipe) is wired in for
// production use, so Close -- which empties the Store -- leaves no
// recoverable key bytes behind.
func TestImportTokens_EvictionZeroizesMaterial(t *testing.T) {
	b, _ := testBackend(t)

	secret := []byte("sensitive wrapping key bytes")
	original := make([]byte, len(secret))
	copy(original, secret)

	if _, err := b.importTokens.Put("evict-me", secret); err != nil {
		t.Fatalf("Put() unexpected error = %v", err)
	}

	b.importTokens.Delete("evict-me")

	allZero := true
	for _, by := range secret {
		if by != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("Delete() must zeroize the evicted key bytes")
	}
}
