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
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestQRDBBearerSurface proves the exported bridge is what a host registers
// with a qrdb node: an unobservable-method authenticator that declines a
// request without a bearer token and admits nothing when no authenticator is
// in force.
func TestQRDBBearerSurface(t *testing.T) {
	var source AuthenticatorSource = NewLiveAuthenticator(nil)
	b := NewQRDBBearerAuthenticator(source)
	var registered qrdbsdk.UnobservableMethodAuthenticator = b
	if !registered.MethodUnobservable() || registered.Name() != "jwt" {
		t.Fatalf("bridge = %q unobservable=%v", registered.Name(), registered.MethodUnobservable())
	}
	if _, err := b.Authenticate(context.Background()); !errors.Is(err, qrdbsdk.ErrUnauthenticated) {
		t.Fatalf("no bearer: err = %v, want qrdb's ErrUnauthenticated", err)
	}
	if ErrBearerNotAccepted == nil {
		t.Fatal("ErrBearerNotAccepted is nil")
	}
}
