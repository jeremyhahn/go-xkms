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

package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc/metadata"
)

// compositeTestAuth is a test double for Authenticator that tracks calls and
// returns configured results. Named distinctly to avoid conflict with
// mockAuthenticator in adaptive_test.go.
type compositeTestAuth struct {
	name       string
	httpResult *Identity
	httpErr    error
	grpcResult *Identity
	grpcErr    error
	httpCalled bool
	grpcCalled bool
}

func (m *compositeTestAuth) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	m.httpCalled = true
	return m.httpResult, m.httpErr
}

func (m *compositeTestAuth) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	m.grpcCalled = true
	return m.grpcResult, m.grpcErr
}

func (m *compositeTestAuth) Name() string {
	return m.name
}

func TestCompositeAuthenticator_NewWithNoAuthenticators(t *testing.T) {
	_, err := NewCompositeAuthenticator()
	if err == nil {
		t.Fatal("NewCompositeAuthenticator() should return error when no authenticators provided")
	}
	if !errors.Is(err, ErrNoAuthenticators) {
		t.Errorf("error = %v, want %v", err, ErrNoAuthenticators)
	}
}

func TestCompositeAuthenticator_Name(t *testing.T) {
	noop := NewNoOpAuthenticator()
	comp, err := NewCompositeAuthenticator(noop)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}
	if comp.Name() != "composite" {
		t.Errorf("Name() = %v, want composite", comp.Name())
	}
}

func TestCompositeAuthenticator_InterfaceCompliance(t *testing.T) {
	// Compile-time check is already in composite.go, but verify at runtime too.
	noop := NewNoOpAuthenticator()
	comp, err := NewCompositeAuthenticator(noop)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}
	var _ Authenticator = comp
}

func TestCompositeAuthenticator_HTTP_FirstSucceeds(t *testing.T) {
	first := &compositeTestAuth{
		name: "first",
		httpResult: &Identity{
			Subject: "first-user",
			Claims:  map[string]interface{}{},
		},
	}
	second := &compositeTestAuth{
		name:    "second",
		httpErr: errors.New("should not be called"),
	}

	comp, err := NewCompositeAuthenticator(first, second)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	identity, err := comp.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}

	if identity.Subject != "first-user" {
		t.Errorf("Subject = %v, want first-user", identity.Subject)
	}
	if !first.httpCalled {
		t.Error("first authenticator should have been called")
	}
	if second.httpCalled {
		t.Error("second authenticator should NOT have been called")
	}
}

func TestCompositeAuthenticator_HTTP_SecondSucceeds(t *testing.T) {
	firstErr := errors.New("first failed")
	first := &compositeTestAuth{
		name:    "first",
		httpErr: firstErr,
	}
	second := &compositeTestAuth{
		name: "second",
		httpResult: &Identity{
			Subject: "second-user",
			Claims:  map[string]interface{}{},
		},
	}

	comp, err := NewCompositeAuthenticator(first, second)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	identity, err := comp.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v", err)
	}

	if identity.Subject != "second-user" {
		t.Errorf("Subject = %v, want second-user", identity.Subject)
	}
	if !first.httpCalled {
		t.Error("first authenticator should have been called")
	}
	if !second.httpCalled {
		t.Error("second authenticator should have been called")
	}
}

func TestCompositeAuthenticator_HTTP_AllFail(t *testing.T) {
	lastErr := errors.New("last error wins")
	first := &compositeTestAuth{
		name:    "first",
		httpErr: errors.New("first failed"),
	}
	second := &compositeTestAuth{
		name:    "second",
		httpErr: errors.New("second failed"),
	}
	third := &compositeTestAuth{
		name:    "third",
		httpErr: lastErr,
	}

	comp, err := NewCompositeAuthenticator(first, second, third)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "/test", nil)
	identity, err := comp.AuthenticateHTTP(req)
	if err == nil {
		t.Fatal("AuthenticateHTTP() should return error when all fail")
	}
	if identity != nil {
		t.Errorf("identity should be nil when all fail, got %v", identity)
	}
	if !errors.Is(err, lastErr) {
		t.Errorf("error = %v, want %v", err, lastErr)
	}
}

func TestCompositeAuthenticator_GRPC_FirstSucceeds(t *testing.T) {
	first := &compositeTestAuth{
		name: "first",
		grpcResult: &Identity{
			Subject: "grpc-first-user",
			Claims:  map[string]interface{}{},
		},
	}
	second := &compositeTestAuth{
		name:    "second",
		grpcErr: errors.New("should not be called"),
	}

	comp, err := NewCompositeAuthenticator(first, second)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	ctx := context.Background()
	md := metadata.New(map[string]string{})
	identity, err := comp.AuthenticateGRPC(ctx, md)
	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v", err)
	}

	if identity.Subject != "grpc-first-user" {
		t.Errorf("Subject = %v, want grpc-first-user", identity.Subject)
	}
	if !first.grpcCalled {
		t.Error("first authenticator should have been called")
	}
	if second.grpcCalled {
		t.Error("second authenticator should NOT have been called")
	}
}

func TestCompositeAuthenticator_GRPC_SecondSucceeds(t *testing.T) {
	first := &compositeTestAuth{
		name:    "first",
		grpcErr: errors.New("first failed"),
	}
	second := &compositeTestAuth{
		name: "second",
		grpcResult: &Identity{
			Subject: "grpc-second-user",
			Claims:  map[string]interface{}{},
		},
	}

	comp, err := NewCompositeAuthenticator(first, second)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	ctx := context.Background()
	md := metadata.New(map[string]string{})
	identity, err := comp.AuthenticateGRPC(ctx, md)
	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v", err)
	}

	if identity.Subject != "grpc-second-user" {
		t.Errorf("Subject = %v, want grpc-second-user", identity.Subject)
	}
	if !first.grpcCalled {
		t.Error("first authenticator should have been called")
	}
	if !second.grpcCalled {
		t.Error("second authenticator should have been called")
	}
}

func TestCompositeAuthenticator_GRPC_AllFail(t *testing.T) {
	lastErr := errors.New("grpc last error")
	first := &compositeTestAuth{
		name:    "first",
		grpcErr: errors.New("first failed"),
	}
	second := &compositeTestAuth{
		name:    "second",
		grpcErr: lastErr,
	}

	comp, err := NewCompositeAuthenticator(first, second)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	ctx := context.Background()
	md := metadata.New(map[string]string{})
	identity, err := comp.AuthenticateGRPC(ctx, md)
	if err == nil {
		t.Fatal("AuthenticateGRPC() should return error when all fail")
	}
	if identity != nil {
		t.Errorf("identity should be nil when all fail, got %v", identity)
	}
	if !errors.Is(err, lastErr) {
		t.Errorf("error = %v, want %v", err, lastErr)
	}
}

func TestCompositeAuthenticator_SingleAuthenticator(t *testing.T) {
	auth := &compositeTestAuth{
		name: "only",
		httpResult: &Identity{
			Subject: "only-user",
			Claims:  map[string]interface{}{},
		},
		grpcResult: &Identity{
			Subject: "only-grpc-user",
			Claims:  map[string]interface{}{},
		},
	}

	comp, err := NewCompositeAuthenticator(auth)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	t.Run("HTTP", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/test", nil)
		identity, err := comp.AuthenticateHTTP(req)
		if err != nil {
			t.Fatalf("AuthenticateHTTP() error = %v", err)
		}
		if identity.Subject != "only-user" {
			t.Errorf("Subject = %v, want only-user", identity.Subject)
		}
	})

	t.Run("GRPC", func(t *testing.T) {
		ctx := context.Background()
		md := metadata.New(map[string]string{})
		identity, err := comp.AuthenticateGRPC(ctx, md)
		if err != nil {
			t.Fatalf("AuthenticateGRPC() error = %v", err)
		}
		if identity.Subject != "only-grpc-user" {
			t.Errorf("Subject = %v, want only-grpc-user", identity.Subject)
		}
	})
}

func TestCompositeAuthenticator_Authenticators(t *testing.T) {
	first := &compositeTestAuth{name: "first"}
	second := &compositeTestAuth{name: "second"}

	comp, err := NewCompositeAuthenticator(first, second)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	auths := comp.Authenticators()
	if len(auths) != 2 {
		t.Fatalf("Authenticators() len = %d, want 2", len(auths))
	}
	if auths[0].Name() != "first" {
		t.Errorf("Authenticators()[0].Name() = %v, want first", auths[0].Name())
	}
	if auths[1].Name() != "second" {
		t.Errorf("Authenticators()[1].Name() = %v, want second", auths[1].Name())
	}
}

func TestCompositeAuthenticator_SliceIsolation(t *testing.T) {
	// Verify that the internal slice is isolated from external mutation.
	first := &compositeTestAuth{name: "first"}
	second := &compositeTestAuth{name: "second"}

	auths := []Authenticator{first, second}
	comp, err := NewCompositeAuthenticator(auths...)
	if err != nil {
		t.Fatalf("NewCompositeAuthenticator() error = %v", err)
	}

	// Mutate the original slice
	auths[0] = nil

	// Composite should be unaffected
	chain := comp.Authenticators()
	if chain[0] == nil {
		t.Error("internal slice should not be affected by external mutation")
	}
}
