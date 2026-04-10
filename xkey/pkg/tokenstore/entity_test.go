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

package tokenstore

import (
	"testing"
	"time"
)

func TestTokenEntity_EntityID_RoundTrip(t *testing.T) {
	e := &TokenEntity{}
	e.SetEntityID(42)
	if got := e.EntityID(); got != 42 {
		t.Fatalf("EntityID() = %d, want 42", got)
	}
}

func TestTokenEntity_ZeroValue(t *testing.T) {
	var e TokenEntity
	if got := e.EntityID(); got != 0 {
		t.Fatalf("zero-value EntityID() = %d, want 0", got)
	}
}

func TestTokenEntity_ToTokenEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	e := &TokenEntity{
		ID:        1,
		ServerURL: "https://example.com",
		TokenType: TypeBearer,
		Source:    SourceOIDC,
		Token:     "jwt-token",
		ExpiresAt: now.Add(time.Hour),
		IssuedAt:  now,
		Issuer:    "https://idp.example.com",
		Subject:   "user@example.com",
	}

	entry := e.ToTokenEntry()

	if entry.ServerURL != e.ServerURL {
		t.Errorf("ServerURL = %q, want %q", entry.ServerURL, e.ServerURL)
	}
	if entry.TokenType != e.TokenType {
		t.Errorf("TokenType = %q, want %q", entry.TokenType, e.TokenType)
	}
	if entry.Source != e.Source {
		t.Errorf("Source = %q, want %q", entry.Source, e.Source)
	}
	if entry.Token != e.Token {
		t.Errorf("Token = %q, want %q", entry.Token, e.Token)
	}
	if !entry.ExpiresAt.Equal(e.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", entry.ExpiresAt, e.ExpiresAt)
	}
	if !entry.IssuedAt.Equal(e.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", entry.IssuedAt, e.IssuedAt)
	}
	if entry.Issuer != e.Issuer {
		t.Errorf("Issuer = %q, want %q", entry.Issuer, e.Issuer)
	}
	if entry.Subject != e.Subject {
		t.Errorf("Subject = %q, want %q", entry.Subject, e.Subject)
	}
}

func TestTokenEntityFromEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	entry := &TokenEntry{
		ServerURL: "https://example.com",
		TokenType: TypeBearer,
		Source:    SourceFIDO2,
		Token:     "fido2-jwt",
		ExpiresAt: now.Add(2 * time.Hour),
		IssuedAt:  now,
		Issuer:    "https://idp.example.com",
		Subject:   "device-001",
	}

	e := TokenEntityFromEntry(entry)

	if e.ID != 0 {
		t.Errorf("new entity ID = %d, want 0", e.ID)
	}
	if e.ServerURL != entry.ServerURL {
		t.Errorf("ServerURL = %q, want %q", e.ServerURL, entry.ServerURL)
	}
	if e.Token != entry.Token {
		t.Errorf("Token = %q, want %q", e.Token, entry.Token)
	}
}
