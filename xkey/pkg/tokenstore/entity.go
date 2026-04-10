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

import "time"

// TokenEntity is the DAO entity representation of a TokenEntry.
// It implements the go-qrdb Entity interface for persistent storage.
type TokenEntity struct {
	ID        uint64    `json:"id"`
	ServerURL string    `json:"server_url" index:"unique,ci"`
	TokenType string    `json:"token_type"`
	Source    string    `json:"source"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
}

// EntityID returns the entity's unique identifier.
func (e *TokenEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *TokenEntity) SetEntityID(id uint64) { e.ID = id }

// ToTokenEntry converts the entity to a TokenEntry domain type.
func (e *TokenEntity) ToTokenEntry() *TokenEntry {
	return &TokenEntry{
		ServerURL: e.ServerURL,
		TokenType: e.TokenType,
		Source:    e.Source,
		Token:     e.Token,
		ExpiresAt: e.ExpiresAt,
		IssuedAt:  e.IssuedAt,
		Issuer:    e.Issuer,
		Subject:   e.Subject,
	}
}

// TokenEntityFromEntry creates a TokenEntity from a TokenEntry domain type.
func TokenEntityFromEntry(entry *TokenEntry) *TokenEntity {
	return &TokenEntity{
		ServerURL: entry.ServerURL,
		TokenType: entry.TokenType,
		Source:    entry.Source,
		Token:     entry.Token,
		ExpiresAt: entry.ExpiresAt,
		IssuedAt:  entry.IssuedAt,
		Issuer:    entry.Issuer,
		Subject:   entry.Subject,
	}
}
