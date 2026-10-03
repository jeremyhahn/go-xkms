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

package types

import (
	"errors"
	"testing"
)

// errNativeCause stands in for a backend's own error.
var errNativeCause = errors.New("native: message authentication failed")

// TestSealedDataAuthenticationError_JoinsCause proves the sentinel and the
// native cause are both reachable, and the message carries the detail.
func TestSealedDataAuthenticationError_JoinsCause(t *testing.T) {
	err := SealedDataAuthenticationError("aead open", errNativeCause)
	if !errors.Is(err, ErrSealedDataAuthentication) {
		t.Fatal("the sentinel must be reachable with errors.Is")
	}
	if !errors.Is(err, errNativeCause) {
		t.Fatal("the native cause must stay reachable with errors.Is")
	}
	want := "sealed data failed authentication: aead open: native: message authentication failed"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// TestSealedDataAuthenticationError_NilCause proves a malformed-envelope
// failure with no native error still matches the sentinel and nothing else.
func TestSealedDataAuthenticationError_NilCause(t *testing.T) {
	err := SealedDataAuthenticationError("nonce is 3 bytes, want 12", nil)
	if !errors.Is(err, ErrSealedDataAuthentication) {
		t.Fatal("the sentinel must be reachable with errors.Is")
	}
	if errors.Is(err, errNativeCause) {
		t.Fatal("no cause was given, so none may match")
	}
	want := "sealed data failed authentication: nonce is 3 bytes, want 12"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// TestErrSealedDataAuthentication_Distinct proves the sentinel is not an
// alias of the signature-path integrity sentinel, so a caller can tell them
// apart.
func TestErrSealedDataAuthentication_Distinct(t *testing.T) {
	if errors.Is(ErrSealedDataAuthentication, ErrIntegrityCheckFailed) ||
		errors.Is(ErrIntegrityCheckFailed, ErrSealedDataAuthentication) {
		t.Fatal("ErrSealedDataAuthentication must be a distinct sentinel")
	}
}
