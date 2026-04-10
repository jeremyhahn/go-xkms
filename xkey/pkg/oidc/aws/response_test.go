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
	"errors"
	"testing"
	"time"
)

func TestParseTokenResponse(t *testing.T) {
	t.Run("valid response with credentials", func(t *testing.T) {
		// This matches the actual AWS signin API response format (snake_case, no wrapper)
		jsonData := `{
			"access_token": {
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"session_token": "FwoGZXIvYXdzEBYaDkExample",
				"expiration": "2025-01-15T12:30:00Z"
			},
			"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in": 900,
			"refresh_token": "refresh456",
			"id_token": "id789"
		}`

		resp, err := ParseTokenResponse([]byte(jsonData))
		if err != nil {
			t.Fatalf("ParseTokenResponse() error = %v", err)
		}

		if resp.TokenType != "urn:aws:params:oauth:token-type:access_token_sigv4" {
			t.Errorf("TokenType = %s, unexpected", resp.TokenType)
		}
		if resp.ExpiresIn != 900 {
			t.Errorf("ExpiresIn = %d, want 900", resp.ExpiresIn)
		}
		if resp.RefreshToken != "refresh456" {
			t.Errorf("RefreshToken = %s, want refresh456", resp.RefreshToken)
		}
		if resp.IDToken != "id789" {
			t.Errorf("IDToken = %s, want id789", resp.IDToken)
		}

		if !resp.HasCredentials() {
			t.Error("HasCredentials() should return true")
		}

		creds := resp.GetCredentials()
		if creds.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("AccessKeyID = %s, unexpected", creds.AccessKeyID)
		}
		if creds.SecretAccessKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
			t.Errorf("SecretAccessKey unexpected")
		}
		if creds.SessionToken != "FwoGZXIvYXdzEBYaDkExample" {
			t.Errorf("SessionToken unexpected")
		}
		if creds.Expiration != "2025-01-15T12:30:00Z" {
			t.Errorf("Expiration = %s, unexpected", creds.Expiration)
		}
	})

	t.Run("error response", func(t *testing.T) {
		jsonData := `{
			"error": "invalid_grant",
			"error_description": "Authorization code has expired"
		}`

		resp, err := ParseTokenResponse([]byte(jsonData))
		if err != nil {
			t.Fatalf("ParseTokenResponse() error = %v", err)
		}

		if !resp.IsError() {
			t.Error("IsError() should return true")
		}
		if resp.Error != "invalid_grant" {
			t.Errorf("Error = %s, want invalid_grant", resp.Error)
		}
		if resp.ErrorDescription != "Authorization code has expired" {
			t.Errorf("ErrorDescription = %s, unexpected", resp.ErrorDescription)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParseTokenResponse([]byte("not json"))
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("Expected ErrInvalidResponse, got %v", err)
		}
	})

	t.Run("missing access_token", func(t *testing.T) {
		// Response without access_token and without error should fail
		jsonData := `{}`

		_, err := ParseTokenResponse([]byte(jsonData))
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("Expected ErrInvalidResponse, got %v", err)
		}
	})

	t.Run("response with only token_type no access_token", func(t *testing.T) {
		// AWS always returns access_token with credentials, so missing it is an error
		jsonData := `{
			"token_type": "Bearer",
			"expires_in": 900
		}`

		_, err := ParseTokenResponse([]byte(jsonData))
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("Expected ErrInvalidResponse for missing access_token, got %v", err)
		}
	})

	t.Run("use_dpop_nonce error", func(t *testing.T) {
		jsonData := `{
			"error": "use_dpop_nonce",
			"error_description": "DPoP nonce required"
		}`

		resp, err := ParseTokenResponse([]byte(jsonData))
		if err != nil {
			t.Fatalf("ParseTokenResponse() error = %v", err)
		}

		if resp.Error != "use_dpop_nonce" {
			t.Errorf("Error = %s, want use_dpop_nonce", resp.Error)
		}
	})
}

func TestTokenResponse_GetExpirationTime(t *testing.T) {
	t.Run("valid RFC3339 format", func(t *testing.T) {
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  "2025-01-15T12:30:00Z",
			},
		}

		expTime, err := resp.GetExpirationTime()
		if err != nil {
			t.Fatalf("GetExpirationTime() error = %v", err)
		}

		expected := time.Date(2025, 1, 15, 12, 30, 0, 0, time.UTC)
		if !expTime.Equal(expected) {
			t.Errorf("GetExpirationTime() = %v, want %v", expTime, expected)
		}
	})

	t.Run("alternative format", func(t *testing.T) {
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  "2025-01-15T12:30:00Z",
			},
		}

		_, err := resp.GetExpirationTime()
		if err != nil {
			t.Fatalf("GetExpirationTime() error = %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		resp := &TokenResponse{}

		_, err := resp.GetExpirationTime()
		if !errors.Is(err, ErrMissingCredentials) {
			t.Errorf("Expected ErrMissingCredentials, got %v", err)
		}
	})

	t.Run("empty expiration", func(t *testing.T) {
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  "",
			},
		}

		_, err := resp.GetExpirationTime()
		if !errors.Is(err, ErrMissingCredentials) {
			t.Errorf("Expected ErrMissingCredentials, got %v", err)
		}
	})

	t.Run("invalid expiration format", func(t *testing.T) {
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  "not-a-date",
			},
		}

		_, err := resp.GetExpirationTime()
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("Expected ErrInvalidResponse, got %v", err)
		}
	})
}

func TestTokenResponse_ToTokenData(t *testing.T) {
	t.Run("with credentials", func(t *testing.T) {
		resp := &TokenResponse{
			RefreshToken: "refresh456",
			IDToken:      "id789",
			TokenType:    "urn:aws:params:oauth:token-type:access_token_sigv4",
			ExpiresIn:    900,
			Credentials: &Credentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
				Expiration:      "2025-01-15T12:30:00Z",
			},
		}

		data, err := resp.ToTokenData("us-east-1")
		if err != nil {
			t.Fatalf("ToTokenData() error = %v", err)
		}

		if data.RefreshToken != "refresh456" {
			t.Errorf("RefreshToken = %s, want refresh456", data.RefreshToken)
		}
		if data.IDToken != "id789" {
			t.Errorf("IDToken = %s, want id789", data.IDToken)
		}
		if data.TokenType != "urn:aws:params:oauth:token-type:access_token_sigv4" {
			t.Errorf("TokenType = %s, unexpected", data.TokenType)
		}
		if data.ExpiresIn != 900 {
			t.Errorf("ExpiresIn = %d, want 900", data.ExpiresIn)
		}

		if data.AWSCredentials == nil {
			t.Fatal("AWSCredentials should not be nil")
		}

		if data.AWSCredentials.AccessKeyID != "AKIAEXAMPLE" {
			t.Errorf("AccessKeyID = %s, want AKIAEXAMPLE", data.AWSCredentials.AccessKeyID)
		}
		if data.AWSCredentials.Region != "us-east-1" {
			t.Errorf("Region = %s, want us-east-1", data.AWSCredentials.Region)
		}
	})

	t.Run("without credentials", func(t *testing.T) {
		resp := &TokenResponse{
			TokenType: "Bearer",
			ExpiresIn: 3600,
		}

		data, err := resp.ToTokenData("eu-west-1")
		if err != nil {
			t.Fatalf("ToTokenData() error = %v", err)
		}

		if data.AWSCredentials != nil {
			t.Error("AWSCredentials should be nil")
		}
		if data.TokenType != "Bearer" {
			t.Errorf("TokenType = %s, want Bearer", data.TokenType)
		}
	})

	t.Run("calculates expiry", func(t *testing.T) {
		resp := &TokenResponse{
			ExpiresIn: 900,
		}

		before := time.Now()
		data, err := resp.ToTokenData("us-east-1")
		if err != nil {
			t.Fatalf("ToTokenData() error = %v", err)
		}
		after := time.Now()

		expectedMin := before.Add(900 * time.Second)
		expectedMax := after.Add(900 * time.Second)

		if data.Expiry.Before(expectedMin) || data.Expiry.After(expectedMax) {
			t.Errorf("Expiry = %v, expected between %v and %v", data.Expiry, expectedMin, expectedMax)
		}
	})
}

func TestTokenResponse_IsCredentialsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		futureTime := time.Now().Add(time.Hour).Format(time.RFC3339)
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  futureTime,
			},
		}

		if resp.IsCredentialsExpired() {
			t.Error("IsCredentialsExpired() should return false for future time")
		}
	})

	t.Run("expired", func(t *testing.T) {
		pastTime := time.Now().Add(-time.Hour).Format(time.RFC3339)
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  pastTime,
			},
		}

		if !resp.IsCredentialsExpired() {
			t.Error("IsCredentialsExpired() should return true for past time")
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		resp := &TokenResponse{}
		if resp.IsCredentialsExpired() {
			t.Error("IsCredentialsExpired() should return false when no credentials")
		}
	})
}

func TestTokenResponse_CredentialsTimeRemaining(t *testing.T) {
	t.Run("has time remaining", func(t *testing.T) {
		futureTime := time.Now().Add(time.Hour).Format(time.RFC3339)
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  futureTime,
			},
		}

		remaining := resp.CredentialsTimeRemaining()
		// Should be close to an hour (with some tolerance for test execution time)
		if remaining < 59*time.Minute || remaining > 61*time.Minute {
			t.Errorf("CredentialsTimeRemaining() = %v, expected ~1h", remaining)
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		resp := &TokenResponse{}
		if resp.CredentialsTimeRemaining() != 0 {
			t.Error("CredentialsTimeRemaining() should return 0 when no credentials")
		}
	})

	t.Run("already expired", func(t *testing.T) {
		pastTime := time.Now().Add(-time.Hour).Format(time.RFC3339)
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "test",
				Expiration:  pastTime,
			},
		}

		remaining := resp.CredentialsTimeRemaining()
		if remaining > 0 {
			t.Errorf("CredentialsTimeRemaining() = %v, expected negative or zero", remaining)
		}
	})
}

func TestTokenResponse_HasCredentials(t *testing.T) {
	t.Run("with full credentials", func(t *testing.T) {
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
			},
		}

		if !resp.HasCredentials() {
			t.Error("HasCredentials() should return true")
		}
	})

	t.Run("with nil credentials", func(t *testing.T) {
		resp := &TokenResponse{}

		if resp.HasCredentials() {
			t.Error("HasCredentials() should return false")
		}
	})

	t.Run("with empty access key", func(t *testing.T) {
		resp := &TokenResponse{
			Credentials: &Credentials{
				AccessKeyID: "",
			},
		}

		if resp.HasCredentials() {
			t.Error("HasCredentials() should return false with empty access key")
		}
	})
}

func TestTokenResponse_IsError(t *testing.T) {
	t.Run("is error", func(t *testing.T) {
		resp := &TokenResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Code expired",
		}

		if !resp.IsError() {
			t.Error("IsError() should return true")
		}
	})

	t.Run("not error", func(t *testing.T) {
		resp := &TokenResponse{
			TokenType: "urn:aws:params:oauth:token-type:access_token_sigv4",
		}

		if resp.IsError() {
			t.Error("IsError() should return false")
		}
	})
}

func TestRawTokenResponse_Structure(t *testing.T) {
	t.Run("full response structure", func(t *testing.T) {
		// Test that the raw structure parses correctly (actual AWS format)
		jsonData := `{
			"access_token": {
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret123",
				"session_token": "session456",
				"expiration": "2025-01-15T12:30:00Z"
			},
			"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in": 900,
			"refresh_token": "refresh789",
			"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
		}`

		resp, err := ParseTokenResponse([]byte(jsonData))
		if err != nil {
			t.Fatalf("ParseTokenResponse() error = %v", err)
		}

		// Verify all fields were extracted correctly
		if resp.TokenType != "urn:aws:params:oauth:token-type:access_token_sigv4" {
			t.Errorf("TokenType = %s, unexpected", resp.TokenType)
		}
		if resp.ExpiresIn != 900 {
			t.Errorf("ExpiresIn = %d, want 900", resp.ExpiresIn)
		}
		if resp.RefreshToken != "refresh789" {
			t.Errorf("RefreshToken = %s, want refresh789", resp.RefreshToken)
		}
		if resp.IDToken != "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." {
			t.Errorf("IDToken mismatch")
		}
		if resp.Credentials.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("AccessKeyID = %s, want AKIAIOSFODNN7EXAMPLE", resp.Credentials.AccessKeyID)
		}
		if resp.Credentials.SecretAccessKey != "secret123" {
			t.Errorf("SecretAccessKey mismatch")
		}
		if resp.Credentials.SessionToken != "session456" {
			t.Errorf("SessionToken mismatch")
		}
	})

	t.Run("minimal response", func(t *testing.T) {
		jsonData := `{
			"access_token": {
				"access_key_id": "AKIATEST"
			},
			"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4"
		}`

		resp, err := ParseTokenResponse([]byte(jsonData))
		if err != nil {
			t.Fatalf("ParseTokenResponse() error = %v", err)
		}

		if resp.Credentials.AccessKeyID != "AKIATEST" {
			t.Errorf("AccessKeyID = %s, want AKIATEST", resp.Credentials.AccessKeyID)
		}
		if resp.RefreshToken != "" {
			t.Errorf("RefreshToken should be empty, got %s", resp.RefreshToken)
		}
	})
}
