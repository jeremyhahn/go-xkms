// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestConsoleResolverFunc_CallsUnderlyingFunc pins the ConsoleResolver
// function-adapter contract.
func TestConsoleResolverFunc_CallsUnderlyingFunc(t *testing.T) {
	want := &sdkssh.ConsoleTarget{Host: "example.test"}
	var gotReq *http.Request
	fn := sdkssh.ConsoleResolverFunc(func(r *http.Request) (*sdkssh.ConsoleTarget, error) {
		gotReq = r
		return want, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	got, err := fn.ResolveConsoleTarget(req)
	if err != nil {
		t.Fatalf("ResolveConsoleTarget: %v", err)
	}
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
	if gotReq != req {
		t.Fatal("the adapter did not forward the *http.Request")
	}
}

// TestNewConsoleWSHandler_ReturnsAHandler pins that the constructor wires a
// non-nil http.Handler over the supplied resolver without requiring a live
// WebSocket round trip.
func TestNewConsoleWSHandler_ReturnsAHandler(t *testing.T) {
	resolver := sdkssh.ConsoleResolverFunc(func(*http.Request) (*sdkssh.ConsoleTarget, error) {
		return nil, errors.New("no target for this test")
	})
	h := sdkssh.NewConsoleWSHandler(resolver)
	if h == nil {
		t.Fatal("NewConsoleWSHandler returned nil")
	}
}

// TestOpenConsole_NilSigner rejects a nil signer with NilInputError before
// attempting to dial.
func TestOpenConsole_NilSigner(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	_, err = sdkssh.OpenConsole(context.Background(), nil, sdkssh.ConsoleRequest{HostKeys: store}, sdkssh.ConsoleConfig{})
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) || nie.Field != "signer" {
		t.Fatalf("expected NilInputError{Field: signer}, got %T: %v", err, err)
	}
}

// TestOpenConsole_NilHostKeys rejects a nil HostKeys store with
// NilInputError before attempting to dial.
func TestOpenConsole_NilHostKeys(t *testing.T) {
	_, err := sdkssh.OpenConsole(context.Background(), testConnectSigner(t), sdkssh.ConsoleRequest{}, sdkssh.ConsoleConfig{})
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) || nie.Field != "HostKeys" {
		t.Fatalf("expected NilInputError{Field: HostKeys}, got %T: %v", err, err)
	}
}

// TestOpenConsole_InvalidScope rejects an unrecognized scope string.
func TestOpenConsole_InvalidScope(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	_, err = sdkssh.OpenConsole(context.Background(), testConnectSigner(t), sdkssh.ConsoleRequest{HostKeys: store, Scope: "not-a-scope"}, sdkssh.ConsoleConfig{})
	var ise *sdkssh.InvalidScopeError
	if !errors.As(err, &ise) {
		t.Fatalf("expected *InvalidScopeError, got %T: %v", err, err)
	}
}

// TestOpenConsoleWithSigners_NoSigners rejects an empty signer list with
// NilInputError before attempting to dial.
func TestOpenConsoleWithSigners_NoSigners(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	_, err = sdkssh.OpenConsoleWithSigners(context.Background(), nil, sdkssh.ConsoleRequest{HostKeys: store}, sdkssh.ConsoleConfig{})
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) || nie.Field != "signers" {
		t.Fatalf("expected NilInputError{Field: signers}, got %T: %v", err, err)
	}
}

// TestOpenConsoleWithSigners_NilHostKeys rejects a nil HostKeys store with
// NilInputError before attempting to dial.
func TestOpenConsoleWithSigners_NilHostKeys(t *testing.T) {
	_, err := sdkssh.OpenConsoleWithSigners(context.Background(), []gossh.Signer{testConnectSigner(t)}, sdkssh.ConsoleRequest{}, sdkssh.ConsoleConfig{})
	var nie *sdkssh.NilInputError
	if !errors.As(err, &nie) || nie.Field != "HostKeys" {
		t.Fatalf("expected NilInputError{Field: HostKeys}, got %T: %v", err, err)
	}
}

// TestOpenConsoleWithSigners_InvalidScope rejects an unrecognized scope
// string.
func TestOpenConsoleWithSigners_InvalidScope(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	_, err = sdkssh.OpenConsoleWithSigners(context.Background(), []gossh.Signer{testConnectSigner(t)},
		sdkssh.ConsoleRequest{HostKeys: store, Scope: "not-a-scope"}, sdkssh.ConsoleConfig{})
	var ise *sdkssh.InvalidScopeError
	if !errors.As(err, &ise) {
		t.Fatalf("expected *InvalidScopeError, got %T: %v", err, err)
	}
}
