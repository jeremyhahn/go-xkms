// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestNewAPIKeyAuthenticator(t *testing.T) {
	tests := []struct {
		name   string
		config *APIKeyConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "custom config",
			config: &APIKeyConfig{
				HeaderName: "X-Custom-Key",
				QueryParam: "custom_key",
				Keys: map[string]*Identity{
					"key1": {
						Subject: "user1",
					},
				},
			},
		},
		{
			name: "empty header name uses default",
			config: &APIKeyConfig{
				HeaderName: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAPIKeyAuthenticator(tt.config)

			if auth == nil {
				t.Fatal("NewAPIKeyAuthenticator() returned nil")
			}

			if auth.headerName == "" {
				t.Error("headerName should not be empty")
			}

			if auth.queryParam == "" {
				t.Error("queryParam should not be empty")
			}

			if auth.validKeys == nil {
				t.Error("validKeys should not be nil")
			}
		})
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_Header(t *testing.T) {
	identity := &Identity{
		Subject: "user1",
		Claims: map[string]interface{}{
			"roles": []string{"admin"},
		},
		Attributes: map[string]string{
			"team": "engineering",
		},
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"test-key-123": identity,
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-API-Key", "test-key-123")
	req.RemoteAddr = "192.168.1.1:12345"

	result, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
	}

	if result.Subject != "user1" {
		t.Errorf("Subject = %v, want user1", result.Subject)
	}

	if result.Attributes["auth_method"] != "apikey" {
		t.Errorf("auth_method = %v, want apikey", result.Attributes["auth_method"])
	}

	if result.Attributes["remote_addr"] != "192.168.1.1:12345" {
		t.Errorf("remote_addr = %v, want 192.168.1.1:12345", result.Attributes["remote_addr"])
	}

	// Verify claims were cloned
	if result.HasRole("admin") != true {
		t.Error("Should have admin role")
	}

	// Verify original attributes were preserved
	if result.Attributes["team"] != "engineering" {
		t.Errorf("team = %v, want engineering", result.Attributes["team"])
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_QueryParam(t *testing.T) {
	identity := &Identity{
		Subject: "user2",
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"test-key-456": identity,
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com?api_key=test-key-456", nil)

	result, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
	}

	if result.Subject != "user2" {
		t.Errorf("Subject = %v, want user2", result.Subject)
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_BearerToken(t *testing.T) {
	identity := &Identity{
		Subject: "user3",
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"test-key-789": identity,
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer test-key-789")

	result, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
	}

	if result.Subject != "user3" {
		t.Errorf("Subject = %v, want user3", result.Subject)
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_InvalidKey(t *testing.T) {
	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"valid-key": {
				Subject: "user1",
			},
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-API-Key", "invalid-key")

	result, err := auth.AuthenticateHTTP(req)

	if err == nil {
		t.Fatal("AuthenticateHTTP() should return error for invalid key")
	}

	if result != nil {
		t.Errorf("AuthenticateHTTP() returned identity %v, want nil", result)
	}

	if err.Error() != "invalid API key" {
		t.Errorf("error = %v, want 'invalid API key'", err)
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_MissingKey(t *testing.T) {
	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"valid-key": {
				Subject: "user1",
			},
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	result, err := auth.AuthenticateHTTP(req)

	if err == nil {
		t.Fatal("AuthenticateHTTP() should return error for missing key")
	}

	if result != nil {
		t.Errorf("AuthenticateHTTP() returned identity %v, want nil", result)
	}

	if err.Error() != "no API key provided" {
		t.Errorf("error = %v, want 'no API key provided'", err)
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_CustomHeaderName(t *testing.T) {
	identity := &Identity{
		Subject: "user4",
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		HeaderName: "X-Custom-Auth",
		Keys: map[string]*Identity{
			"custom-key": identity,
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Custom-Auth", "custom-key")

	result, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
	}

	if result.Subject != "user4" {
		t.Errorf("Subject = %v, want user4", result.Subject)
	}
}

func TestAPIKeyAuthenticator_AuthenticateHTTP_CustomQueryParam(t *testing.T) {
	identity := &Identity{
		Subject: "user5",
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		QueryParam: "token",
		Keys: map[string]*Identity{
			"query-key": identity,
		},
	})

	reqURL, _ := url.Parse("http://example.com")
	query := reqURL.Query()
	query.Set("token", "query-key")
	reqURL.RawQuery = query.Encode()

	req, _ := http.NewRequest("GET", reqURL.String(), nil)

	result, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateHTTP() returned nil identity")
	}

	if result.Subject != "user5" {
		t.Errorf("Subject = %v, want user5", result.Subject)
	}
}

func TestAPIKeyAuthenticator_AuthenticateGRPC_ValidKey(t *testing.T) {
	identity := &Identity{
		Subject: "grpc-user",
		Claims: map[string]interface{}{
			"permissions": []string{"read", "write"},
		},
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"grpc-key": identity,
		},
	})

	md := metadata.New(map[string]string{
		"x-api-key": "grpc-key",
	})

	result, err := auth.AuthenticateGRPC(context.Background(), md)

	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateGRPC() returned nil identity")
	}

	if result.Subject != "grpc-user" {
		t.Errorf("Subject = %v, want grpc-user", result.Subject)
	}

	if result.Attributes["auth_method"] != "apikey" {
		t.Errorf("auth_method = %v, want apikey", result.Attributes["auth_method"])
	}
}

func TestAPIKeyAuthenticator_AuthenticateGRPC_BearerToken(t *testing.T) {
	identity := &Identity{
		Subject: "bearer-user",
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"bearer-key": identity,
		},
	})

	md := metadata.New(map[string]string{
		"authorization": "Bearer bearer-key",
	})

	result, err := auth.AuthenticateGRPC(context.Background(), md)

	if err != nil {
		t.Fatalf("AuthenticateGRPC() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("AuthenticateGRPC() returned nil identity")
	}

	if result.Subject != "bearer-user" {
		t.Errorf("Subject = %v, want bearer-user", result.Subject)
	}
}

func TestAPIKeyAuthenticator_AuthenticateGRPC_InvalidKey(t *testing.T) {
	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"valid-key": {
				Subject: "user1",
			},
		},
	})

	md := metadata.New(map[string]string{
		"x-api-key": "invalid-key",
	})

	result, err := auth.AuthenticateGRPC(context.Background(), md)

	if err == nil {
		t.Fatal("AuthenticateGRPC() should return error for invalid key")
	}

	if result != nil {
		t.Errorf("AuthenticateGRPC() returned identity %v, want nil", result)
	}

	if err.Error() != "invalid API key" {
		t.Errorf("error = %v, want 'invalid API key'", err)
	}
}

func TestAPIKeyAuthenticator_AuthenticateGRPC_MissingKey(t *testing.T) {
	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"valid-key": {
				Subject: "user1",
			},
		},
	})

	md := metadata.New(map[string]string{})

	result, err := auth.AuthenticateGRPC(context.Background(), md)

	if err == nil {
		t.Fatal("AuthenticateGRPC() should return error for missing key")
	}

	if result != nil {
		t.Errorf("AuthenticateGRPC() returned identity %v, want nil", result)
	}

	if err.Error() != "no API key provided in metadata" {
		t.Errorf("error = %v, want 'no API key provided in metadata'", err)
	}
}

func TestAPIKeyAuthenticator_AddKey(t *testing.T) {
	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{},
	})

	identity := &Identity{
		Subject: "new-user",
	}

	auth.AddKey("new-key", identity)

	// Verify the key was added by trying to authenticate
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-API-Key", "new-key")

	result, err := auth.AuthenticateHTTP(req)

	if err != nil {
		t.Fatalf("AuthenticateHTTP() error = %v, want nil after AddKey", err)
	}

	if result.Subject != "new-user" {
		t.Errorf("Subject = %v, want new-user", result.Subject)
	}
}

func TestAPIKeyAuthenticator_RemoveKey(t *testing.T) {
	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"remove-me": {
				Subject: "temp-user",
			},
		},
	})

	// Verify key exists
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-API-Key", "remove-me")

	result, err := auth.AuthenticateHTTP(req)
	if err != nil {
		t.Fatalf("Key should exist before removal: %v", err)
	}

	if result.Subject != "temp-user" {
		t.Error("Key should be valid before removal")
	}

	// Remove the key
	auth.RemoveKey("remove-me")

	// Verify key is removed
	result, err = auth.AuthenticateHTTP(req)

	if err == nil {
		t.Fatal("AuthenticateHTTP() should return error after RemoveKey")
	}

	if result != nil {
		t.Error("Should not authenticate after key removal")
	}
}

func TestAPIKeyAuthenticator_Name(t *testing.T) {
	auth := NewAPIKeyAuthenticator(nil)

	name := auth.Name()

	if name != "apikey" {
		t.Errorf("Name() = %v, want apikey", name)
	}
}

func TestAPIKeyAuthenticator_CloneProtection(t *testing.T) {
	// Test that modifying the returned identity doesn't affect the stored one
	originalIdentity := &Identity{
		Subject: "user1",
		Claims: map[string]interface{}{
			"role": "admin",
		},
		Attributes: map[string]string{
			"team": "engineering",
		},
	}

	auth := NewAPIKeyAuthenticator(&APIKeyConfig{
		Keys: map[string]*Identity{
			"test-key": originalIdentity,
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-API-Key", "test-key")

	result1, _ := auth.AuthenticateHTTP(req)

	// Modify the returned identity
	result1.Subject = "modified"
	result1.Claims["role"] = "guest"
	result1.Attributes["team"] = "support"

	// Get another identity and verify it's not modified
	result2, _ := auth.AuthenticateHTTP(req)

	if result2.Subject != "user1" {
		t.Errorf("Subject was modified, got %v, want user1", result2.Subject)
	}

	if result2.Claims["role"] != "admin" {
		t.Errorf("Claims were modified, got %v, want admin", result2.Claims["role"])
	}

	if result2.Attributes["team"] != "engineering" {
		t.Errorf("Attributes were modified, got %v, want engineering", result2.Attributes["team"])
	}
}
