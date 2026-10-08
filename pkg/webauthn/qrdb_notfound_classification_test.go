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

// The user classifier decides whether a lookup failure means "this user is
// absent" or "the user service could not answer". These tests assert the
// REFUSALS: that errors which merely look like a not-found are not treated as
// one.

// TestUserClassifierFailsClosed pins that the classifier never matches on
// message text. Until #183 it fell back to a substring probe, so a transport
// failure that mentioned "not found" made the registration ceremony create a
// duplicate account.
func TestUserClassifierFailsClosed(t *testing.T) {
	for _, looksLikeNotFound := range []error{
		errors.New("transport failed: no rows"),
		errors.New("connection not found"),
		errors.New("dial tcp 10.0.0.1:7443: connect: host not found"),
	} {
		if isUserNotFound(looksLikeNotFound) {
			t.Fatalf("the user classifier must not match on message text: %v", looksLikeNotFound)
		}
	}
}

// TestMapNotFoundRefusesTransportFailure is the user-store half of
// TestMapNotFoundCredRefusesTransportFailure: a store that cannot answer
// produces an error, never ErrUserNotFound, which is what licenses the
// ceremony's implicit account creation.
func TestMapNotFoundRefusesTransportFailure(t *testing.T) {
	transportErr := errors.New("qrdb: session not found, reconnecting")

	got := mapNotFound(transportErr)

	if errors.Is(got, ErrUserNotFound) {
		t.Fatal("a transport failure must not be reported as a missing user")
	}
	if !errors.Is(got, transportErr) {
		t.Fatalf("the underlying failure must be preserved for the caller, got %v", got)
	}
}

// TestMapNotFoundReportsAGenuineMissOnEveryTransportShape is the positive
// half for the user store: each shape a missing user takes on the pinned
// SDK still maps to ErrUserNotFound, so the inversion has not broken
// registration on any transport.
func TestMapNotFoundReportsAGenuineMissOnEveryTransportShape(t *testing.T) {
	for name, err := range map[string]error{
		"REST":            &qrdbtransport.UserNotFoundError{ID: 7},
		"gRPC/MCP/embed":  &qrdbtransport.KeyNotFoundError{Key: "7"},
		"QUIC canonical":  &qrdbtransport.RequestError{Method: "GetUser", Err: errors.New("user not found: 7")},
		"wrapped by qrdb": fmt.Errorf("users: %w", &qrdbtransport.UserNotFoundError{ID: 7}),
	} {
		t.Run(name, func(t *testing.T) {
			if got := mapNotFound(err); !errors.Is(got, ErrUserNotFound) {
				t.Fatalf("a genuinely absent user must map to ErrUserNotFound, got %v", got)
			}
		})
	}
}
