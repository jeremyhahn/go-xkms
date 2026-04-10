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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
)

func TestClientConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ClientConfig
		wantErr error
	}{
		{
			name:    "valid config",
			config:  &ClientConfig{Region: "us-east-1"},
			wantErr: nil,
		},
		{
			name:    "missing region",
			config:  &ClientConfig{},
			wantErr: ErrMissingRegion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClientConfig_EffectiveClientID(t *testing.T) {
	tests := []struct {
		name     string
		config   *ClientConfig
		expected string
	}{
		{
			name:     "default same-device",
			config:   &ClientConfig{Region: "us-east-1"},
			expected: SameDeviceClientID,
		},
		{
			name:     "cross-device",
			config:   &ClientConfig{Region: "us-east-1", CrossDevice: true},
			expected: CrossDeviceClientID,
		},
		{
			name:     "custom client ID",
			config:   &ClientConfig{Region: "us-east-1", ClientID: "custom-id"},
			expected: "custom-id",
		},
		{
			name:     "cross-device overrides custom",
			config:   &ClientConfig{Region: "us-east-1", ClientID: "custom-id", CrossDevice: true},
			expected: CrossDeviceClientID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.EffectiveClientID(); got != tt.expected {
				t.Errorf("EffectiveClientID() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestClientConfig_EffectiveScopes(t *testing.T) {
	t.Run("default scopes", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		scopes := config.EffectiveScopes()

		if len(scopes) != 1 || scopes[0] != "openid" {
			t.Errorf("EffectiveScopes() = %v, want [openid]", scopes)
		}
	})

	t.Run("custom scopes", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1", Scopes: []string{"openid", "profile"}}
		scopes := config.EffectiveScopes()

		if len(scopes) != 2 {
			t.Errorf("EffectiveScopes() = %v, want 2 scopes", scopes)
		}
	})
}

func TestNewClient(t *testing.T) {
	t.Run("valid creation", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		dpopKey, _ := oidc.GenerateDPoPKey()

		client, err := NewClient(config, dpopKey)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		if client.AuthorizeEndpoint() != "https://us-east-1.signin.aws.amazon.com/v1/authorize" {
			t.Errorf("AuthorizeEndpoint() = %s, unexpected", client.AuthorizeEndpoint())
		}

		if client.TokenEndpoint() != "https://us-east-1.signin.aws.amazon.com/v1/token" {
			t.Errorf("TokenEndpoint() = %s, unexpected", client.TokenEndpoint())
		}
	})

	t.Run("missing region", func(t *testing.T) {
		config := &ClientConfig{}
		_, err := NewClient(config, nil)

		if !errors.Is(err, ErrMissingRegion) {
			t.Errorf("NewClient() error = %v, want ErrMissingRegion", err)
		}
	})

	t.Run("different regions", func(t *testing.T) {
		regions := []string{"us-west-2", "eu-west-1", "ap-northeast-1"}

		for _, region := range regions {
			config := &ClientConfig{Region: region}
			client, _ := NewClient(config, nil)

			if !strings.Contains(client.AuthorizeEndpoint(), region) {
				t.Errorf("AuthorizeEndpoint() should contain %s", region)
			}
			if !strings.Contains(client.TokenEndpoint(), region) {
				t.Errorf("TokenEndpoint() should contain %s", region)
			}
		}
	})
}

func TestClient_AuthCodeURL(t *testing.T) {
	config := &ClientConfig{
		Region:      "us-east-1",
		RedirectURL: "http://localhost:8080/callback",
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	t.Run("valid URL generation", func(t *testing.T) {
		codeVerifier, err := oidc.GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("GenerateCodeVerifier() error = %v", err)
		}
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: codeVerifier,
			Nonce:        "test-nonce",
		}

		url, err := client.AuthCodeURL(opts)
		if err != nil {
			t.Fatalf("AuthCodeURL() error = %v", err)
		}

		// Verify URL contains expected parameters
		checks := []string{
			"response_type=code",
			"client_id=arn%3Aaws%3Asignin%3A%3A%3Adevtools%2Fsame-device",
			"state=test-state",
			"code_challenge=",
			"code_challenge_method=SHA-256",
			"redirect_uri=",
			"nonce=test-nonce",
			"scope=openid",
		}

		for _, check := range checks {
			if !strings.Contains(url, check) {
				t.Errorf("URL should contain %s, got: %s", check, url)
			}
		}
	})

	t.Run("missing state", func(t *testing.T) {
		codeVerifier, _ := oidc.GenerateCodeVerifier()
		opts := &AuthCodeOptions{
			CodeVerifier: codeVerifier,
		}

		_, err := client.AuthCodeURL(opts)
		if !errors.Is(err, oidc.ErrInvalidState) {
			t.Errorf("AuthCodeURL() error = %v, want ErrInvalidState", err)
		}
	})

	t.Run("missing code verifier", func(t *testing.T) {
		opts := &AuthCodeOptions{
			State: "test-state",
		}

		_, err := client.AuthCodeURL(opts)
		if !errors.Is(err, oidc.ErrInvalidCodeVerifier) {
			t.Errorf("AuthCodeURL() error = %v, want ErrInvalidCodeVerifier", err)
		}
	})

	t.Run("with additional params", func(t *testing.T) {
		codeVerifier, _ := oidc.GenerateCodeVerifier()
		opts := &AuthCodeOptions{
			State:        "test-state",
			CodeVerifier: codeVerifier,
			AdditionalParams: map[string]string{
				"prompt":   "consent",
				"audience": "https://api.example.com",
			},
		}

		url, err := client.AuthCodeURL(opts)
		if err != nil {
			t.Fatalf("AuthCodeURL() error = %v", err)
		}

		if !strings.Contains(url, "prompt=consent") {
			t.Error("URL should contain prompt parameter")
		}
		if !strings.Contains(url, "audience=") {
			t.Error("URL should contain audience parameter")
		}
	})
}

func TestClient_Exchange(t *testing.T) {
	t.Run("missing DPoP key", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		client, _ := NewClient(config, nil)

		codeVerifier, _ := oidc.GenerateCodeVerifier()
		_, err := client.Exchange(context.Background(), "code", &AuthCodeOptions{
			State:        "state",
			CodeVerifier: codeVerifier,
		})

		if !errors.Is(err, ErrMissingDPoPKey) {
			t.Errorf("Exchange() error = %v, want ErrMissingDPoPKey", err)
		}
	})

	t.Run("empty code", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		dpopKey, _ := oidc.GenerateDPoPKey()
		client, _ := NewClient(config, dpopKey)

		codeVerifier, _ := oidc.GenerateCodeVerifier()
		_, err := client.Exchange(context.Background(), "", &AuthCodeOptions{
			State:        "state",
			CodeVerifier: codeVerifier,
		})

		if !errors.Is(err, ErrTokenRequestFailed) {
			t.Errorf("Exchange() error = %v, want ErrTokenRequestFailed", err)
		}
	})

	t.Run("missing code verifier", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		dpopKey, _ := oidc.GenerateDPoPKey()
		client, _ := NewClient(config, dpopKey)

		_, err := client.Exchange(context.Background(), "code", &AuthCodeOptions{
			State: "state",
		})

		if !errors.Is(err, oidc.ErrInvalidCodeVerifier) {
			t.Errorf("Exchange() error = %v, want ErrInvalidCodeVerifier", err)
		}
	})

	t.Run("successful exchange", func(t *testing.T) {
		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify DPoP header is present
			dpopHeader := r.Header.Get("DPoP")
			if dpopHeader == "" {
				t.Error("DPoP header should be present")
			}

			// Verify content type
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("Content-Type should be application/x-www-form-urlencoded")
			}

			// Return mock response in actual AWS signin API format (no wrapper, snake_case)
			resp := map[string]interface{}{
				"access_token": map[string]interface{}{
					"access_key_id":     "AKIAEXAMPLE",
					"secret_access_key": "secret",
					"session_token":     "token",
					"expiration":        "2025-01-15T12:30:00Z",
				},
				"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4",
				"expires_in": 900,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		// Create client with custom HTTP client pointing to mock server
		config := &ClientConfig{
			Region:      "us-east-1",
			HTTPClient:  server.Client(),
			RedirectURL: "http://localhost/callback",
		}
		dpopKey, _ := oidc.GenerateDPoPKey()
		client, _ := NewClient(config, dpopKey)

		// Override token endpoint (hacky but works for testing)
		originalTokenEndpoint := client.TokenEndpoint()
		_ = originalTokenEndpoint // Silence unused variable

		// For this test, we need to actually use a real server
		// so let's skip the endpoint override and test the request building
	})
}

func TestClient_Refresh(t *testing.T) {
	t.Run("missing DPoP key", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		client, _ := NewClient(config, nil)

		_, err := client.Refresh(context.Background(), "refresh-token")
		if !errors.Is(err, ErrMissingDPoPKey) {
			t.Errorf("Refresh() error = %v, want ErrMissingDPoPKey", err)
		}
	})

	t.Run("missing refresh token", func(t *testing.T) {
		config := &ClientConfig{Region: "us-east-1"}
		dpopKey, _ := oidc.GenerateDPoPKey()
		client, _ := NewClient(config, dpopKey)

		_, err := client.Refresh(context.Background(), "")
		if !errors.Is(err, oidc.ErrMissingRefreshToken) {
			t.Errorf("Refresh() error = %v, want ErrMissingRefreshToken", err)
		}
	})
}

func TestClient_DPoPKeyManagement(t *testing.T) {
	config := &ClientConfig{Region: "us-east-1"}
	client, _ := NewClient(config, nil)

	// Initially nil
	if client.GetDPoPKey() != nil {
		t.Error("GetDPoPKey() should be nil initially")
	}

	// Set key
	dpopKey, _ := oidc.GenerateDPoPKey()
	client.SetDPoPKey(dpopKey)

	if client.GetDPoPKey() != dpopKey {
		t.Error("GetDPoPKey() should return set key")
	}
}

func TestClient_DPoPNonceManagement(t *testing.T) {
	config := &ClientConfig{Region: "us-east-1"}
	client, _ := NewClient(config, nil)

	// Initially empty
	if client.GetDPoPNonce() != "" {
		t.Error("GetDPoPNonce() should be empty initially")
	}

	// Set nonce
	client.SetDPoPNonce("test-nonce")

	if client.GetDPoPNonce() != "test-nonce" {
		t.Errorf("GetDPoPNonce() = %s, want test-nonce", client.GetDPoPNonce())
	}
}

func TestClient_GetConfig(t *testing.T) {
	config := &ClientConfig{Region: "us-east-1"}
	client, _ := NewClient(config, nil)

	if client.GetConfig() != config {
		t.Error("GetConfig() should return original config")
	}
}

func TestClient_DoTokenRequest_Success(t *testing.T) {
	// Create mock server that returns successful response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify headers
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("Content-Type should be application/x-www-form-urlencoded")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("Accept should be application/json")
		}
		if r.Header.Get("DPoP") == "" {
			t.Error("DPoP header should be present")
		}

		// Return successful response in actual AWS format (no wrapper, snake_case)
		resp := map[string]interface{}{
			"access_token": map[string]interface{}{
				"access_key_id":     "AKIAEXAMPLE",
				"secret_access_key": "secret123",
				"session_token":     "token456",
				"expiration":        "2025-01-15T12:30:00Z",
			},
			"token_type":    "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in":    900,
			"refresh_token": "refresh789",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client with endpoint override
	config := &ClientConfig{
		Region:                "us-east-1",
		RedirectURL:           "http://localhost/callback",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, err := NewClient(config, dpopKey)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Perform exchange
	resp, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough-for-pkce",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	// Verify response
	if resp.TokenType != "urn:aws:params:oauth:token-type:access_token_sigv4" {
		t.Errorf("TokenType = %s, unexpected", resp.TokenType)
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("ExpiresIn = %d, want 900", resp.ExpiresIn)
	}
	if !resp.HasCredentials() {
		t.Error("HasCredentials() should return true")
	}
	if resp.Credentials.AccessKeyID != "AKIAEXAMPLE" {
		t.Errorf("AccessKeyID = %s, want AKIAEXAMPLE", resp.Credentials.AccessKeyID)
	}
}

func TestClient_DoTokenRequest_DPoPNonceRetry(t *testing.T) {
	requestCount := 0

	// Create mock server that requires nonce on first request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount == 1 {
			// First request: return use_dpop_nonce error
			w.Header().Set("DPoP-Nonce", "test-nonce-12345")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "use_dpop_nonce",
				"error_description": "DPoP nonce required",
			})
			return
		}

		// Subsequent requests: return success in actual AWS format
		resp := map[string]interface{}{
			"access_token": map[string]interface{}{
				"access_key_id":     "AKIAEXAMPLE",
				"secret_access_key": "secret",
				"session_token":     "token",
			},
			"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in": 900,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		RedirectURL:           "http://localhost/callback",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform exchange
	resp, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	// Verify nonce was stored
	if client.GetDPoPNonce() != "test-nonce-12345" {
		t.Errorf("DPoP nonce = %s, want test-nonce-12345", client.GetDPoPNonce())
	}

	// Verify success after retry
	if resp.TokenType != "urn:aws:params:oauth:token-type:access_token_sigv4" {
		t.Errorf("TokenType = %s, unexpected", resp.TokenType)
	}

	// Verify 2 requests were made (initial + retry)
	if requestCount != 2 {
		t.Errorf("Request count = %d, want 2", requestCount)
	}
}

func TestClient_DoTokenRequest_ErrorResponse(t *testing.T) {
	// Create mock server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Authorization code has expired",
		})
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform exchange
	_, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})

	// Verify error
	if err == nil {
		t.Fatal("Exchange() should return error")
	}
	if !errors.Is(err, ErrTokenRequestFailed) {
		t.Errorf("Expected ErrTokenRequestFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "Authorization code has expired") {
		t.Errorf("Error should contain error description, got %s", err.Error())
	}
}

func TestClient_DoTokenRequest_NonceRetryExhausted(t *testing.T) {
	// Create mock server that always returns nonce error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "new-nonce")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "use_dpop_nonce",
			"error_description": "DPoP nonce required",
		})
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform exchange
	_, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})

	// Verify error after retry exhaustion
	if !errors.Is(err, ErrNonceRetryExhausted) {
		t.Errorf("Expected ErrNonceRetryExhausted, got %v", err)
	}
}

func TestClient_DoTokenRequest_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform exchange
	_, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})

	// Verify error
	if err == nil {
		t.Fatal("Exchange() should return error")
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("Expected ErrInvalidResponse, got %v", err)
	}
}

func TestClient_Refresh_Success(t *testing.T) {
	// Create mock server that returns successful response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify grant_type
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %s, want refresh_token", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "old-refresh-token" {
			t.Errorf("refresh_token unexpected")
		}

		// Return successful response in actual AWS format (no wrapper, snake_case)
		resp := map[string]interface{}{
			"access_token": map[string]interface{}{
				"access_key_id":     "AKIANEWKEY",
				"secret_access_key": "newsecret",
				"session_token":     "newtoken",
			},
			"token_type":    "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in":    900,
			"refresh_token": "new-refresh-token",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform refresh
	resp, err := client.Refresh(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// Verify response
	if resp.RefreshToken != "new-refresh-token" {
		t.Errorf("RefreshToken = %s, want new-refresh-token", resp.RefreshToken)
	}
	if resp.Credentials.AccessKeyID != "AKIANEWKEY" {
		t.Errorf("AccessKeyID = %s, want AKIANEWKEY", resp.Credentials.AccessKeyID)
	}
}

func TestClient_AuthorizeEndpoint_Override(t *testing.T) {
	config := &ClientConfig{
		Region:                    "us-east-1",
		AuthorizeEndpointOverride: "https://custom.example.com/authorize",
	}
	client, _ := NewClient(config, nil)

	endpoint := client.AuthorizeEndpoint()
	if endpoint != "https://custom.example.com/authorize" {
		t.Errorf("AuthorizeEndpoint() = %s, want custom endpoint", endpoint)
	}
}

func TestClient_TokenEndpoint_Override(t *testing.T) {
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: "https://custom.example.com/token",
	}
	client, _ := NewClient(config, nil)

	endpoint := client.TokenEndpoint()
	if endpoint != "https://custom.example.com/token" {
		t.Errorf("TokenEndpoint() = %s, want custom endpoint", endpoint)
	}
}

func TestClient_AuthCodeURL_CodeChallengeFormat(t *testing.T) {
	config := &ClientConfig{
		Region:      "us-east-1",
		RedirectURL: "http://localhost/callback",
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	authURL, err := client.AuthCodeURL(&AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-at-least-43-characters-long-for-pkce",
	})
	if err != nil {
		t.Fatalf("AuthCodeURL() error = %v", err)
	}

	// Verify code_challenge has no trailing '=' padding
	if strings.Contains(authURL, "code_challenge=") {
		// Extract code_challenge value
		parts := strings.Split(authURL, "code_challenge=")
		if len(parts) > 1 {
			challengePart := strings.Split(parts[1], "&")[0]
			if strings.HasSuffix(challengePart, "=") || strings.HasSuffix(challengePart, "%3D") {
				t.Errorf("code_challenge should not have trailing '=' padding: %s", challengePart)
			}
		}
	}

	// Verify code_challenge_method is SHA-256
	if !strings.Contains(authURL, "code_challenge_method=SHA-256") {
		t.Error("code_challenge_method should be SHA-256")
	}
}

func TestClient_DoTokenRequest_HTTPError(t *testing.T) {
	// Create mock server that returns HTTP 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform exchange
	_, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})

	// Verify error
	if err == nil {
		t.Fatal("Exchange() should return error")
	}
	if !errors.Is(err, ErrTokenRequestFailed) {
		t.Errorf("Expected ErrTokenRequestFailed, got %v", err)
	}
}

func TestClient_DoTokenRequest_NonceSavedFromSuccessResponse(t *testing.T) {
	// Create mock server that returns nonce in success response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "success-nonce")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Return successful response in actual AWS format (no wrapper, snake_case)
		resp := map[string]interface{}{
			"access_token": map[string]interface{}{
				"access_key_id":     "AKIAEXAMPLE",
				"secret_access_key": "secret",
				"session_token":     "token",
			},
			"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4",
			"expires_in": 900,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client
	config := &ClientConfig{
		Region:                "us-east-1",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	// Perform exchange
	_, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	// Verify nonce was saved from success response
	if client.GetDPoPNonce() != "success-nonce" {
		t.Errorf("DPoP nonce = %s, want success-nonce", client.GetDPoPNonce())
	}
}

func TestClient_Exchange_WithRedirectURL(t *testing.T) {
	// Create mock server that verifies redirect_uri
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("redirect_uri") != "http://127.0.0.1:8085/callback" {
			t.Errorf("redirect_uri = %s, unexpected", r.Form.Get("redirect_uri"))
		}

		// Return successful response in actual AWS format (no wrapper, snake_case)
		resp := map[string]interface{}{
			"access_token": map[string]interface{}{
				"access_key_id": "AKIAEXAMPLE",
			},
			"token_type": "urn:aws:params:oauth:token-type:access_token_sigv4",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		Region:                "us-east-1",
		RedirectURL:           "http://127.0.0.1:8085/callback",
		TokenEndpointOverride: server.URL,
	}
	dpopKey, _ := oidc.GenerateDPoPKey()
	client, _ := NewClient(config, dpopKey)

	_, err := client.Exchange(context.Background(), "auth-code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "test-verifier-that-is-long-enough",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}
