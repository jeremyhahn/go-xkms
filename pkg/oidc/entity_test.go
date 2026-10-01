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

package oidc

import "testing"

func TestOIDCTokenEntity_EntityID_RoundTrip(t *testing.T) {
	e := &OIDCTokenEntity{}
	e.SetEntityID(7)
	if got := e.EntityID(); got != 7 {
		t.Fatalf("EntityID() = %d, want 7", got)
	}
}

func TestOIDCTokenEntity_ZeroValue(t *testing.T) {
	var e OIDCTokenEntity
	if got := e.EntityID(); got != 0 {
		t.Fatalf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestOIDCTokenEntity_ToTokenResponse(t *testing.T) {
	e := &OIDCTokenEntity{
		ID:           1,
		Issuer:       "https://idp.example.com",
		AccessToken:  "access-abc",
		RefreshToken: "refresh-xyz",
		IDToken:      "id-token-123",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		Scope:        "openid profile",
		DPoPKeyPEM:   "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----",
	}

	resp := e.ToTokenResponse()

	if resp.AccessToken != e.AccessToken {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, e.AccessToken)
	}
	if resp.RefreshToken != e.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", resp.RefreshToken, e.RefreshToken)
	}
	if resp.IDToken != e.IDToken {
		t.Errorf("IDToken = %q, want %q", resp.IDToken, e.IDToken)
	}
	if resp.ExpiresIn != e.ExpiresIn {
		t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, e.ExpiresIn)
	}
	if resp.TokenType != e.TokenType {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, e.TokenType)
	}
	if resp.Scope != e.Scope {
		t.Errorf("Scope = %q, want %q", resp.Scope, e.Scope)
	}
	if resp.DPoPKeyPEM != e.DPoPKeyPEM {
		t.Errorf("DPoPKeyPEM = %q, want %q", resp.DPoPKeyPEM, e.DPoPKeyPEM)
	}
}

func TestOIDCTokenEntityFromResponse(t *testing.T) {
	resp := &TokenResponse{
		AccessToken:  "at-1",
		TokenType:    "Bearer",
		RefreshToken: "rt-1",
		ExpiresIn:    7200,
		IDToken:      "idt-1",
		Scope:        "openid",
	}

	e := OIDCTokenEntityFromResponse("https://idp.example.com", resp)

	if e.ID != 0 {
		t.Errorf("new entity ID = %d, want 0", e.ID)
	}
	if e.Issuer != "https://idp.example.com" {
		t.Errorf("Issuer = %q, want %q", e.Issuer, "https://idp.example.com")
	}
	if e.AccessToken != resp.AccessToken {
		t.Errorf("AccessToken = %q, want %q", e.AccessToken, resp.AccessToken)
	}
	if e.ExpiresIn != resp.ExpiresIn {
		t.Errorf("ExpiresIn = %d, want %d", e.ExpiresIn, resp.ExpiresIn)
	}
}
