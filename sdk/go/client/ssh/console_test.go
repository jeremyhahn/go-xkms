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

// TestNewConsoleWSHandler_ResolverErrorIsForbidden pins that the handler
// resolves (and can reject) BEFORE ever attempting the WebSocket upgrade: a
// resolver failure must surface as 403 without needing a live socket.
func TestNewConsoleWSHandler_ResolverErrorIsForbidden(t *testing.T) {
	resolver := sdkssh.ConsoleResolverFunc(func(*http.Request) (*sdkssh.ConsoleTarget, error) {
		return nil, errors.New("caller not authorized for this host")
	})
	h := sdkssh.NewConsoleWSHandler(resolver)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ssh/console", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestNewConsoleWSHandler_InvalidScopeIsForbidden pins that an unrecognized
// ConsoleTarget.Scope string from the resolver is rejected with the same
// *InvalidScopeError -> 403 path as a resolver-level authorization failure,
// rather than reaching the dial stage with a zero-value scope.
func TestNewConsoleWSHandler_InvalidScopeIsForbidden(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	resolver := sdkssh.ConsoleResolverFunc(func(*http.Request) (*sdkssh.ConsoleTarget, error) {
		return &sdkssh.ConsoleTarget{
			Host: "server.example.test", Port: 22, User: "deploy",
			Signer: testConnectSigner(t), HostKeys: store, Scope: "not-a-scope",
		}, nil
	})
	h := sdkssh.NewConsoleWSHandler(resolver)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ssh/console", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestNewConsoleWSHandler_ValidScopeReachesUpgrade pins that a resolver
// returning a fully valid ConsoleTarget (including a non-default, valid
// Scope) carries the request past scope parsing to the WebSocket upgrade
// attempt: a plain (non-WebSocket) request fails the upgrade with 400,
// distinct from the 403 the two error-path tests above pin, proving
// resolution and scope parsing both succeeded.
func TestNewConsoleWSHandler_ValidScopeReachesUpgrade(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	resolver := sdkssh.ConsoleResolverFunc(func(*http.Request) (*sdkssh.ConsoleTarget, error) {
		return &sdkssh.ConsoleTarget{
			Host: "server.example.test", Port: 22, User: "deploy",
			Signer: testConnectSigner(t), HostKeys: store, Scope: "tenant", Owner: "acme",
		}, nil
	})
	h := sdkssh.NewConsoleWSHandler(resolver)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ssh/console", nil))
	if rec.Code == http.StatusForbidden {
		t.Fatal("a valid target must not be rejected as forbidden")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d for a failed (non-WebSocket) upgrade", rec.Code, http.StatusBadRequest)
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

// TestOpenConsole_ValidScopeReachesDial pins that a valid, non-default
// Scope string is parsed and carries the request past validation into
// pkgconsole.Dial: targeting a closed local port, the resulting error must
// not be *InvalidScopeError, proving the scope was accepted rather than
// rejected before the dial was attempted.
func TestOpenConsole_ValidScopeReachesDial(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	host, port := closedTCPAddr(t)
	_, err = sdkssh.OpenConsole(context.Background(), testConnectSigner(t), sdkssh.ConsoleRequest{
		Host: host, Port: port, User: "deploy", HostKeys: store, Scope: "tenant", Owner: "acme",
	}, sdkssh.ConsoleConfig{})
	if err == nil {
		t.Fatal("expected a dial-stage error against a closed port")
	}
	var ise *sdkssh.InvalidScopeError
	if errors.As(err, &ise) {
		t.Fatalf("a valid scope must not be rejected: %v", err)
	}
}

// TestOpenConsoleWithSigners_ValidScopeReachesDial mirrors
// TestOpenConsole_ValidScopeReachesDial for the multi-signer entry point.
func TestOpenConsoleWithSigners_ValidScopeReachesDial(t *testing.T) {
	store, err := sdkssh.NewHostKeyStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewHostKeyStore: %v", err)
	}
	host, port := closedTCPAddr(t)
	_, err = sdkssh.OpenConsoleWithSigners(context.Background(), []gossh.Signer{testConnectSigner(t)}, sdkssh.ConsoleRequest{
		Host: host, Port: port, User: "deploy", HostKeys: store, Scope: "tenant", Owner: "acme",
	}, sdkssh.ConsoleConfig{})
	if err == nil {
		t.Fatal("expected a dial-stage error against a closed port")
	}
	var ise *sdkssh.InvalidScopeError
	if errors.As(err, &ise) {
		t.Fatalf("a valid scope must not be rejected: %v", err)
	}
}
