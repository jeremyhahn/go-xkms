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

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// TokenResponse represents the response from the token endpoint.
type TokenResponse struct {
	// AccessToken is the access token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// TokenType is the type of the token issued (typically "Bearer").
	TokenType string `json:"token_type"`

	// RefreshToken is the refresh token for obtaining new access tokens.
	RefreshToken string `json:"refresh_token,omitempty"`

	// ExpiresIn is the lifetime of the access token in seconds.
	ExpiresIn int `json:"expires_in,omitempty"`

	// IDToken is the ID token containing user identity claims.
	IDToken string `json:"id_token,omitempty"`

	// Scope is the scope of the access token.
	Scope string `json:"scope,omitempty"`

	// Expiry is the calculated expiry time of the access token.
	Expiry time.Time `json:"expiry,omitempty"`

	// DPoPKeyPEM is the PEM-encoded EC private key for DPoP token binding.
	// RFC 9449 requires the same key for refresh to maintain binding.
	// Encrypted at rest via BackendTokenStore (barrier).
	DPoPKeyPEM string `json:"dpop_key_pem,omitempty"`
}

// IsExpired returns true if the access token has expired.
// Includes a 10-second buffer to account for clock skew.
func (t *TokenResponse) IsExpired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return time.Now().Add(10 * time.Second).After(t.Expiry)
}

// Valid returns true if the token response contains a valid access token.
func (t *TokenResponse) Valid() bool {
	return t.AccessToken != "" && !t.IsExpired()
}

// GetDPoPKey deserializes the stored DPoP PEM key into a DPoPKey.
// Returns nil and ErrDPoPInvalidProof if no key is stored or deserialization fails.
func (t *TokenResponse) GetDPoPKey() (*DPoPKey, error) {
	if t.DPoPKeyPEM == "" {
		return nil, ErrDPoPInvalidProof
	}
	return DeserializeDPoPKey(t.DPoPKeyPEM)
}

// SetDPoPKey serializes the DPoP key to PEM and stores it on the token response.
func (t *TokenResponse) SetDPoPKey(key *DPoPKey) error {
	if key == nil {
		return ErrDPoPKeyGeneration
	}
	pem, err := key.SerializePrivateKey()
	if err != nil {
		return err
	}
	t.DPoPKeyPEM = pem
	return nil
}

// InheritFrom completes a refresh response from the token set it replaced.
// RFC 6749 section 6 lets a provider omit the refresh token (the old one
// stays valid) and the ID token from a refresh response; a provider that
// rotates refresh tokens returns a new one, which is kept. The DPoP key is
// always carried over: RFC 9449 binds the refreshed tokens to the same key.
func (t *TokenResponse) InheritFrom(prev *TokenResponse) {
	if prev == nil {
		return
	}
	if t.RefreshToken == "" {
		t.RefreshToken = prev.RefreshToken
	}
	if t.IDToken == "" {
		t.IDToken = prev.IDToken
	}
	if t.Scope == "" {
		t.Scope = prev.Scope
	}
	if t.TokenType == "" {
		t.TokenType = prev.TokenType
	}
	if t.DPoPKeyPEM == "" {
		t.DPoPKeyPEM = prev.DPoPKeyPEM
	}
}

// ExpiresAt returns when the access token expires: the Expiry the token
// endpoint reported, or, when it reported none, the "exp" claim of a JWT
// access token. The zero time means the expiry is unknown.
//
// The claim is read without verifying the token's signature. It is used only
// to schedule a refresh, never to trust the token.
func (t *TokenResponse) ExpiresAt() time.Time {
	if !t.Expiry.IsZero() {
		return t.Expiry
	}
	exp, ok := JWTExpiry(t.AccessToken)
	if !ok {
		return time.Time{}
	}
	return exp
}

// JWTExpiry returns the "exp" claim of a compact JWT, read without verifying
// its signature, and ok=false when token is not a JWT or carries no "exp".
func JWTExpiry(token string) (time.Time, bool) {
	claims, ok := UnverifiedClaims(token)
	if !ok {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// UnverifiedClaims decodes the claims of a compact JWT WITHOUT verifying its
// signature, and ok=false when token is not a three-part JWT with a JSON
// object payload. Its result must never be trusted for an authorization
// decision; it serves bookkeeping such as scheduling a refresh or naming the
// account a token belongs to.
func UnverifiedClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

// IDTokenClaims represents the standard claims in an OIDC ID token.
type IDTokenClaims struct {
	// Issuer is the identifier for the issuer of the token.
	Issuer string `json:"iss"`

	// Subject is the unique identifier for the user.
	Subject string `json:"sub"`

	// Audience is the client ID(s) this token is intended for.
	// Can be a single string or array of strings.
	Audience Audience `json:"aud"`

	// Expiry is the expiration time of the token (Unix timestamp).
	Expiry int64 `json:"exp"`

	// IssuedAt is the time the token was issued (Unix timestamp).
	IssuedAt int64 `json:"iat"`

	// AuthTime is the time the user was authenticated (Unix timestamp).
	AuthTime int64 `json:"auth_time,omitempty"`

	// Nonce is the nonce value used to associate the client session.
	Nonce string `json:"nonce,omitempty"`

	// AuthorizedParty is the client ID to which the ID Token was issued.
	AuthorizedParty string `json:"azp,omitempty"`

	// AccessTokenHash is the hash of the access token.
	AccessTokenHash string `json:"at_hash,omitempty"`

	// CodeHash is the hash of the authorization code.
	CodeHash string `json:"c_hash,omitempty"`

	// AuthenticationContextClassReference indicates the authentication context class.
	ACR string `json:"acr,omitempty"`

	// AuthenticationMethodsReferences lists the authentication methods used.
	AMR []string `json:"amr,omitempty"`

	// Email is the user's email address.
	Email string `json:"email,omitempty"`

	// EmailVerified indicates if the email has been verified.
	EmailVerified bool `json:"email_verified,omitempty"`

	// Name is the user's full name.
	Name string `json:"name,omitempty"`

	// GivenName is the user's first name.
	GivenName string `json:"given_name,omitempty"`

	// FamilyName is the user's last name.
	FamilyName string `json:"family_name,omitempty"`

	// PreferredUsername is the user's preferred username.
	PreferredUsername string `json:"preferred_username,omitempty"`

	// Picture is the URL of the user's profile picture.
	Picture string `json:"picture,omitempty"`

	// Profile is the URL of the user's profile page.
	Profile string `json:"profile,omitempty"`

	// Locale is the user's locale.
	Locale string `json:"locale,omitempty"`

	// Zoneinfo is the user's timezone.
	Zoneinfo string `json:"zoneinfo,omitempty"`

	// UpdatedAt is the time the user's information was last updated (Unix timestamp).
	UpdatedAt int64 `json:"updated_at,omitempty"`

	// PhoneNumber is the user's phone number.
	PhoneNumber string `json:"phone_number,omitempty"`

	// PhoneNumberVerified indicates if the phone number has been verified.
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`

	// Address is the user's address as a JSON object.
	Address *Address `json:"address,omitempty"`

	// Extra contains any additional claims not covered by standard fields.
	Extra map[string]interface{} `json:"-"`
}

// Audience represents the audience claim which can be a single string or array.
type Audience []string

// Contains checks if the audience contains the specified value.
func (a Audience) Contains(value string) bool {
	for _, v := range a {
		if v == value {
			return true
		}
	}
	return false
}

// Address represents the address claim in the ID token.
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// ExpiryTime returns the expiry as a time.Time value.
func (c *IDTokenClaims) ExpiryTime() time.Time {
	return time.Unix(c.Expiry, 0)
}

// IssuedAtTime returns the issued at time as a time.Time value.
func (c *IDTokenClaims) IssuedAtTime() time.Time {
	return time.Unix(c.IssuedAt, 0)
}

// AuthenticationTime returns the authentication time as a time.Time value.
func (c *IDTokenClaims) AuthenticationTime() time.Time {
	return time.Unix(c.AuthTime, 0)
}

// IsExpired returns true if the ID token has expired.
func (c *IDTokenClaims) IsExpired() bool {
	return time.Now().After(c.ExpiryTime())
}

// UserInfo represents the user information returned from the userinfo endpoint.
type UserInfo struct {
	Subject           string  `json:"sub"`
	Name              string  `json:"name,omitempty"`
	GivenName         string  `json:"given_name,omitempty"`
	FamilyName        string  `json:"family_name,omitempty"`
	PreferredUsername string  `json:"preferred_username,omitempty"`
	Email             string  `json:"email,omitempty"`
	EmailVerified     bool    `json:"email_verified,omitempty"`
	Picture           string  `json:"picture,omitempty"`
	Profile           string  `json:"profile,omitempty"`
	Locale            string  `json:"locale,omitempty"`
	Zoneinfo          string  `json:"zoneinfo,omitempty"`
	Address           Address `json:"address,omitempty"`
}
