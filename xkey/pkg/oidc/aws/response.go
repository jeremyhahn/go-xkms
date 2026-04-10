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

package aws

import (
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
)

// RawTokenResponse represents the raw AWS signin API response.
// The access_token field is an object containing AWS credentials (not a string).
type RawTokenResponse struct {
	// AccessToken contains AWS credentials (this is an object, not a string).
	AccessToken *AccessTokenCredentials `json:"access_token,omitempty"`

	// TokenType is the type of token.
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the token expiration in seconds.
	ExpiresIn int `json:"expires_in,omitempty"`

	// RefreshToken for refreshing the session.
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken is the OIDC ID token.
	IDToken string `json:"id_token,omitempty"`

	// Error fields (OAuth2 standard)
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// AccessTokenCredentials represents the AWS credentials in the access_token field.
type AccessTokenCredentials struct {
	// AccessKeyID is the AWS access key ID.
	AccessKeyID string `json:"access_key_id"`

	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string `json:"secret_access_key"`

	// SessionToken is the AWS session token.
	SessionToken string `json:"session_token"`

	// Expiration is when the credentials expire (ISO 8601 format).
	Expiration string `json:"expiration,omitempty"`
}

// TokenResponse represents the normalized AWS OIDC token response.
// This provides a consistent interface for the rest of the codebase.
type TokenResponse struct {
	// TokenType is the type of token (e.g., "DPoP").
	TokenType string

	// ExpiresIn is the token expiration in seconds.
	ExpiresIn int

	// RefreshToken for refreshing the session.
	RefreshToken string

	// IDToken is the OIDC ID token.
	IDToken string

	// Credentials contains the AWS temporary credentials.
	Credentials *Credentials

	// Error fields
	Error            string
	ErrorDescription string
}

// Credentials represents AWS temporary security credentials.
type Credentials struct {
	// AccessKeyID is the AWS access key ID.
	AccessKeyID string

	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string

	// SessionToken is the AWS session token.
	SessionToken string

	// Expiration is when the credentials expire (ISO 8601 format).
	Expiration string
}

// ErrorResponse represents an AWS OIDC error response.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// ParseTokenResponse parses a raw JSON response into a TokenResponse.
func ParseTokenResponse(data []byte) (*TokenResponse, error) {
	var raw RawTokenResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, ErrInvalidResponse
	}

	// Check for error response
	if raw.Error != "" {
		return &TokenResponse{
			Error:            raw.Error,
			ErrorDescription: raw.ErrorDescription,
		}, nil
	}

	// Validate response structure - must have access_token with credentials
	if raw.AccessToken == nil {
		return nil, ErrInvalidResponse
	}

	// Convert to normalized response
	resp := &TokenResponse{
		TokenType:    raw.TokenType,
		ExpiresIn:    raw.ExpiresIn,
		RefreshToken: raw.RefreshToken,
		IDToken:      raw.IDToken,
	}

	// Extract credentials from access_token object
	resp.Credentials = &Credentials{
		AccessKeyID:     raw.AccessToken.AccessKeyID,
		SecretAccessKey: raw.AccessToken.SecretAccessKey,
		SessionToken:    raw.AccessToken.SessionToken,
		Expiration:      raw.AccessToken.Expiration,
	}

	return resp, nil
}

// IsError returns true if the response contains an error.
func (r *TokenResponse) IsError() bool {
	return r.Error != ""
}

// HasCredentials returns true if the response contains AWS credentials.
func (r *TokenResponse) HasCredentials() bool {
	return r.Credentials != nil && r.Credentials.AccessKeyID != ""
}

// GetCredentials returns the AWS credentials from the response.
func (r *TokenResponse) GetCredentials() *Credentials {
	return r.Credentials
}

// GetExpirationTime parses and returns the credential expiration time.
func (r *TokenResponse) GetExpirationTime() (time.Time, error) {
	creds := r.GetCredentials()
	if creds == nil || creds.Expiration == "" {
		return time.Time{}, ErrMissingCredentials
	}

	// AWS uses ISO 8601 format
	t, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		// Try alternative formats
		t, err = time.Parse("2006-01-02T15:04:05Z", creds.Expiration)
		if err != nil {
			return time.Time{}, ErrInvalidResponse
		}
	}
	return t, nil
}

// ToTokenData converts the AWS response to the handlers.TokenData format.
func (r *TokenResponse) ToTokenData(region string) (*handlers.TokenData, error) {
	data := &handlers.TokenData{
		RefreshToken: r.RefreshToken,
		IDToken:      r.IDToken,
		TokenType:    r.TokenType,
		ExpiresIn:    r.ExpiresIn,
	}

	// Calculate token expiry
	if r.ExpiresIn > 0 {
		data.Expiry = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)
	}

	// Convert AWS credentials if present
	if r.HasCredentials() {
		creds := r.GetCredentials()
		expiration, _ := r.GetExpirationTime()

		data.AWSCredentials = &handlers.AWSCredentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Expiration:      expiration,
			Region:          region,
		}
	}

	return data, nil
}

// IsCredentialsExpired returns true if the credentials have expired.
func (r *TokenResponse) IsCredentialsExpired() bool {
	expiration, err := r.GetExpirationTime()
	if err != nil {
		return false
	}
	return time.Now().After(expiration)
}

// CredentialsTimeRemaining returns the time remaining until credentials expire.
func (r *TokenResponse) CredentialsTimeRemaining() time.Duration {
	expiration, err := r.GetExpirationTime()
	if err != nil {
		return 0
	}
	return time.Until(expiration)
}
