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

// OIDCTokenEntity is the DAO entity representation of an OIDC TokenResponse.
// It implements the go-qrdb Entity interface for persistent storage.
type OIDCTokenEntity struct {
	ID           uint64 `json:"id"`
	Issuer       string `json:"issuer" index:"unique,ci"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	DPoPKeyPEM   string `json:"dpop_key_pem"`
}

// EntityID returns the entity's unique identifier.
func (e *OIDCTokenEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's unique identifier.
func (e *OIDCTokenEntity) SetEntityID(id uint64) { e.ID = id }

// ToTokenResponse converts the entity to a TokenResponse domain type.
func (e *OIDCTokenEntity) ToTokenResponse() *TokenResponse {
	return &TokenResponse{
		AccessToken:  e.AccessToken,
		TokenType:    e.TokenType,
		RefreshToken: e.RefreshToken,
		ExpiresIn:    e.ExpiresIn,
		IDToken:      e.IDToken,
		Scope:        e.Scope,
		DPoPKeyPEM:   e.DPoPKeyPEM,
	}
}

// OIDCTokenEntityFromResponse creates an OIDCTokenEntity from an issuer
// string and a TokenResponse domain type.
func OIDCTokenEntityFromResponse(issuer string, resp *TokenResponse) *OIDCTokenEntity {
	return &OIDCTokenEntity{
		Issuer:       issuer,
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
		IDToken:      resp.IDToken,
		Scope:        resp.Scope,
		DPoPKeyPEM:   resp.DPoPKeyPEM,
	}
}
