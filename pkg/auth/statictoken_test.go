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

package auth

import (
	"context"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/metadata"
)

func newStaticAuth() *StaticTokenAuthenticator {
	return NewStaticTokenAuthenticator("secret-token", Identity{
		Subject:  "desktop-owner",
		TenantID: "system",
		Roles:    []string{"admin"},
	})
}

func TestStaticToken_AcceptsLoopbackWithToken(t *testing.T) {
	a := newStaticAuth()
	req := httptest.NewRequest("GET", "/api/v1/keys", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Authorization", "Bearer secret-token")

	id, err := a.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id.Subject != "desktop-owner" || id.TenantID != "system" {
		t.Errorf("unexpected identity: %+v", id)
	}
	if id.Metadata["auth_method"] != "loopback-token" {
		t.Errorf("expected loopback-token auth_method, got %q", id.Metadata["auth_method"])
	}
	if len(id.Roles) != 1 || id.Roles[0] != "admin" {
		t.Errorf("expected admin role, got %v", id.Roles)
	}
}

func TestStaticToken_RejectsWrongToken(t *testing.T) {
	a := newStaticAuth()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer wrong")

	if _, err := a.AuthenticateHTTP(req); err == nil {
		t.Fatal("expected failure for wrong token")
	}
}

func TestStaticToken_RejectsMissingToken(t *testing.T) {
	a := newStaticAuth()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"

	if _, err := a.AuthenticateHTTP(req); err == nil {
		t.Fatal("expected failure with no Authorization header")
	}
}

func TestStaticToken_RejectsNonLoopback(t *testing.T) {
	a := newStaticAuth()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("Authorization", "Bearer secret-token")

	// Even the correct token must be refused off the loopback interface.
	if _, err := a.AuthenticateHTTP(req); err == nil {
		t.Fatal("expected failure for non-loopback remote with valid token")
	}
}

func TestStaticToken_RejectsGRPC(t *testing.T) {
	a := newStaticAuth()
	if _, err := a.AuthenticateGRPC(context.Background(), metadata.New(nil)); err == nil {
		t.Fatal("expected gRPC authentication to be refused")
	}
}

func TestStaticToken_IdentityIsCopied(t *testing.T) {
	a := newStaticAuth()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Authorization", "Bearer secret-token")

	first, err := a.AuthenticateHTTP(req)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the returned identity must not affect the next result.
	first.Metadata["tampered"] = "yes"
	first.Roles[0] = "attacker"

	second, err := a.AuthenticateHTTP(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second.Metadata["tampered"]; ok {
		t.Error("identity metadata leaked between requests")
	}
	if second.Roles[0] != "admin" {
		t.Errorf("identity roles leaked between requests: %v", second.Roles)
	}
}

func TestStaticToken_Name(t *testing.T) {
	if newStaticAuth().Name() != "statictoken" {
		t.Errorf("unexpected name %q", newStaticAuth().Name())
	}
}

func TestIsLoopbackRemote(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8443", true},
		{"[::1]:8443", true},
		{"127.0.0.1", true},
		{"10.0.0.1:443", false},
		{"192.168.1.5:80", false},
		{"garbage", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackRemote(c.addr); got != c.want {
			t.Errorf("isLoopbackRemote(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
