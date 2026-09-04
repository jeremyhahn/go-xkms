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

package webauthn

import (
	"errors"
	"fmt"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// The key-value classifier decides whether a lookup failure means "this
// credential is absent" or "the store could not answer". Every caller treats
// the first as benign, so a transport failure classified as not-found becomes a
// silent, wrong answer in the authentication path.
//
// These tests assert the REFUSALS: that errors which merely look like a
// not-found are not treated as one.

// TestIsKVNotFoundAcceptsOnlyTheTypedError proves classification is positive
// and typed. Anything not recognised is an error, not an absent key.
func TestIsKVNotFoundAcceptsOnlyTheTypedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"the typed key-not-found", &qrdbtransport.KeyNotFoundError{Key: "cred/abc"}, true},
		{"typed, wrapped", fmt.Errorf("read credential: %w",
			&qrdbtransport.KeyNotFoundError{Key: "cred/abc"}), true},

		// Everything below is a FAILURE to answer, not an answer of "absent".
		// Each one was classified as not-found before this change.
		{"a transport failure whose text says not found",
			errors.New("dial tcp 10.0.0.1:7443: connect: host not found"), false},
		{"a driver error mentioning no rows",
			errors.New("read tcp: connection reset while scanning, no rows buffered"), false},
		{"an error naming the qrdb code in prose",
			errors.New("gateway timeout translating ErrCodeNotFound"), false},
		{"a plain transport failure", errors.New("transport unavailable"), false},
		{"a context deadline", errors.New("context deadline exceeded"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isKVNotFound(c.err); got != c.want {
				t.Fatalf("isKVNotFound(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestMapNotFoundCredRefusesTransportFailure proves the refusal reaches the
// caller: a store that cannot answer produces an error, not
// ErrCredentialNotFound. Returning the sentinel here tells a relying party the
// credential does not exist, on the strength of a network failure.
func TestMapNotFoundCredRefusesTransportFailure(t *testing.T) {
	transportErr := errors.New("qrdb: connection refused, no rows to read")

	got := mapNotFoundCred(transportErr)

	if errors.Is(got, ErrCredentialNotFound) {
		t.Fatal("a transport failure must not be reported as a missing credential")
	}
	if !errors.Is(got, transportErr) {
		t.Fatalf("the underlying failure must be preserved for the caller, got %v", got)
	}
}

// TestMapNotFoundCredReportsAGenuineMiss is the positive half: a real absent
// key still maps to the sentinel, so the inversion has not simply broken
// lookups.
func TestMapNotFoundCredReportsAGenuineMiss(t *testing.T) {
	got := mapNotFoundCred(&qrdbtransport.KeyNotFoundError{Key: "cred/abc"})

	if !errors.Is(got, ErrCredentialNotFound) {
		t.Fatalf("a genuinely absent credential must map to ErrCredentialNotFound, got %v", got)
	}
}

// TestUserAndKVClassifiersAreDistinct pins the deliberate asymmetry. The KV
// classifier is typed and fails closed; the user classifier still matches text
// and fails open, because UserClient's not-found contract is unconfirmed
// (go-qrdb#286). Collapsing them in either direction is a behaviour change:
// one way re-opens the KV path, the other breaks registration.
func TestUserAndKVClassifiersAreDistinct(t *testing.T) {
	looksLikeNotFound := errors.New("transport failed: no rows")

	if isKVNotFound(looksLikeNotFound) {
		t.Fatal("the KV classifier must not match on message text")
	}
	if !isUserNotFound(looksLikeNotFound) {
		t.Fatal("the user classifier still matches on text; see go-qrdb#286 before changing this")
	}
}
