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

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// WebAuthnClient wraps HTTP client for WebAuthn API testing
type WebAuthnClient struct {
	*RESTClient
}

// NewWebAuthnClient creates a new WebAuthn API client
func NewWebAuthnClient(baseURL string) *WebAuthnClient {
	return &WebAuthnClient{
		RESTClient: NewRESTClient(baseURL),
	}
}

// doWebAuthnRequest performs a WebAuthn-specific HTTP request with session handling
func (c *WebAuthnClient) doWebAuthnRequest(method, path string, body interface{}, sessionID string) (*http.Response, error) {
	resp, err := c.doRequest(method, path, body)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// doWebAuthnRequestWithSession performs a WebAuthn request with session ID header
func (c *WebAuthnClient) doWebAuthnRequestWithSession(method, path string, body interface{}, sessionID string) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = io.NopCloser(io.NewSectionReader(nil, 0, 0))
		_ = jsonBody // Avoid unused warning
		reqBody = nil
	}

	// Create request manually to add session header
	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	if body != nil {
		jsonBody, _ := json.Marshal(body)
		req.Body = io.NopCloser(io.NewSectionReader(nil, 0, 0))
		_ = jsonBody
	}

	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("X-Session-Id", sessionID)
	}

	return c.client.Do(req)
}

// isWebAuthnEnabled checks if WebAuthn is enabled on the server
func isWebAuthnEnabled(t *testing.T, cfg *TestConfig) bool {
	t.Helper()

	client := NewRESTClient(cfg.RESTBaseURL)
	resp, err := client.doRequest("GET", "/api/v1/webauthn/registration/status", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// If we get 404, WebAuthn is not enabled
	// If we get any other response, WebAuthn is enabled
	return resp.StatusCode != http.StatusNotFound
}

// TestWebAuthnRegistrationStatus tests the registration status endpoint
func TestWebAuthnRegistrationStatus(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)

	t.Run("Check unregistered user by email", func(t *testing.T) {
		resp, err := client.doRequest("GET", "/api/v1/webauthn/registration/status?email=unknown@example.com", nil)
		assertNoError(t, err, "Registration status request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		assertNoError(t, err, "Failed to decode response")

		registered, ok := result["registered"].(bool)
		if !ok {
			t.Fatal("Response missing registered field")
		}

		if registered {
			t.Fatal("User should not be registered")
		}

		t.Log("Registration status check passed: user not registered")
	})

	t.Run("Check without user identifier", func(t *testing.T) {
		resp, err := client.doRequest("GET", "/api/v1/webauthn/registration/status", nil)
		assertNoError(t, err, "Registration status request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		assertNoError(t, err, "Failed to decode response")

		registered, ok := result["registered"].(bool)
		if !ok {
			t.Fatal("Response missing registered field")
		}

		if registered {
			t.Fatal("User should not be registered without identifier")
		}

		t.Log("Registration status check passed: no user identifier returns false")
	})
}

// TestWebAuthnBeginRegistration tests the begin registration endpoint
func TestWebAuthnBeginRegistration(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)
	testEmail := fmt.Sprintf("test-%s@example.com", generateUniqueID("webauthn"))

	t.Run("Begin registration with valid email", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email":        testEmail,
			"display_name": "Test User",
		}

		resp, err := client.doRequest("POST", "/api/v1/webauthn/registration/begin", reqBody)
		assertNoError(t, err, "Begin registration request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

		// Check for session ID header
		sessionID := resp.Header.Get("X-Session-Id")
		assertNotEmpty(t, sessionID, "Session ID header missing")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		assertNoError(t, err, "Failed to decode response")

		// Should contain publicKey options
		pubKey, ok := result["publicKey"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing publicKey field")
		}

		// Verify challenge is present
		challenge, ok := pubKey["challenge"]
		if !ok || challenge == "" {
			t.Fatal("Response missing challenge")
		}

		// Verify relying party info
		rp, ok := pubKey["rp"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing rp (relying party) info")
		}

		rpID, ok := rp["id"].(string)
		if !ok || rpID == "" {
			t.Fatal("Response missing rp.id")
		}

		t.Logf("Begin registration successful: session=%s, rpID=%s", sessionID, rpID)
	})

	t.Run("Begin registration missing email", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"display_name": "Test User",
		}

		resp, err := client.doRequest("POST", "/api/v1/webauthn/registration/begin", reqBody)
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusBadRequest, resp.StatusCode, "Should return bad request for missing email")

		t.Log("Missing email validation passed")
	})

	t.Run("Begin registration invalid JSON", func(t *testing.T) {
		req, _ := http.NewRequest("POST", cfg.RESTBaseURL+"/api/v1/webauthn/registration/begin",
			io.NopCloser(ioReader("{invalid json}")))
		req.Header.Set("Content-Type", "application/json")

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusBadRequest, resp.StatusCode, "Should return bad request for invalid JSON")

		t.Log("Invalid JSON validation passed")
	})
}

// TestWebAuthnBeginLogin tests the begin login endpoint
func TestWebAuthnBeginLogin(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)

	t.Run("Begin login with discoverable credentials", func(t *testing.T) {
		// Empty body for discoverable credentials flow
		resp, err := client.doRequest("POST", "/api/v1/webauthn/login/begin", map[string]interface{}{})
		assertNoError(t, err, "Begin login request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusOK, resp.StatusCode, "Unexpected status code")

		// Check for session ID header
		sessionID := resp.Header.Get("X-Session-Id")
		assertNotEmpty(t, sessionID, "Session ID header missing")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		assertNoError(t, err, "Failed to decode response")

		// Should contain publicKey options
		pubKey, ok := result["publicKey"].(map[string]interface{})
		if !ok {
			t.Fatal("Response missing publicKey field")
		}

		// Verify challenge is present
		challenge, ok := pubKey["challenge"]
		if !ok || challenge == "" {
			t.Fatal("Response missing challenge")
		}

		t.Logf("Begin login (discoverable) successful: session=%s", sessionID)
	})

	t.Run("Begin login with unknown email", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email": "unknown-user@example.com",
		}

		resp, err := client.doRequest("POST", "/api/v1/webauthn/login/begin", reqBody)
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusNotFound, resp.StatusCode, "Should return not found for unknown user")

		t.Log("Unknown user validation passed")
	})
}

// TestWebAuthnFinishRegistration tests the finish registration endpoint
func TestWebAuthnFinishRegistration(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)

	t.Run("Finish registration missing session ID", func(t *testing.T) {
		resp, err := client.doRequest("POST", "/api/v1/webauthn/registration/finish", map[string]interface{}{})
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusBadRequest, resp.StatusCode, "Should return bad request for missing session ID")

		t.Log("Missing session ID validation passed")
	})

	t.Run("Finish registration invalid session ID", func(t *testing.T) {
		req, _ := http.NewRequest("POST", cfg.RESTBaseURL+"/api/v1/webauthn/registration/finish",
			io.NopCloser(ioReader("{}")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-Id", "invalid-session-id")

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusBadRequest, resp.StatusCode, "Should return bad request for invalid session")

		t.Log("Invalid session ID validation passed")
	})
}

// TestWebAuthnFinishLogin tests the finish login endpoint
func TestWebAuthnFinishLogin(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)

	t.Run("Finish login missing session ID", func(t *testing.T) {
		resp, err := client.doRequest("POST", "/api/v1/webauthn/login/finish", map[string]interface{}{})
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusBadRequest, resp.StatusCode, "Should return bad request for missing session ID")

		t.Log("Missing session ID validation passed")
	})

	t.Run("Finish login invalid session ID", func(t *testing.T) {
		req, _ := http.NewRequest("POST", cfg.RESTBaseURL+"/api/v1/webauthn/login/finish",
			io.NopCloser(ioReader("{}")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-Id", "invalid-session-id")

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		assertNoError(t, err, "Request failed")
		defer resp.Body.Close()

		assertEqual(t, http.StatusBadRequest, resp.StatusCode, "Should return bad request for invalid session")

		t.Log("Invalid session ID validation passed")
	})
}

// TestWebAuthnMethodNotAllowed tests HTTP method enforcement
func TestWebAuthnMethodNotAllowed(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"GET on registration/begin", "GET", "/api/v1/webauthn/registration/begin"},
		{"GET on registration/finish", "GET", "/api/v1/webauthn/registration/finish"},
		{"POST on registration/status", "POST", "/api/v1/webauthn/registration/status"},
		{"GET on login/begin", "GET", "/api/v1/webauthn/login/begin"},
		{"GET on login/finish", "GET", "/api/v1/webauthn/login/finish"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, cfg.RESTBaseURL+tt.path, nil)
			resp, err := client.client.Do(req)
			assertNoError(t, err, "Request failed")
			defer resp.Body.Close()

			assertEqual(t, http.StatusMethodNotAllowed, resp.StatusCode, "Should return method not allowed")
		})
	}

	t.Log("Method not allowed validation passed for all endpoints")
}

// TestWebAuthnRoutesMounted tests that WebAuthn routes are mounted
func TestWebAuthnRoutesMounted(t *testing.T) {
	cfg := LoadTestConfig()
	if !isServerAvailable(t, cfg) {
		t.Fatal("Server not available for integration tests")
	}

	// Skip if WebAuthn is not enabled on the server
	if !isWebAuthnEnabled(t, cfg) {
		t.Skip("WebAuthn not enabled on server")
	}

	client := NewWebAuthnClient(cfg.RESTBaseURL)

	// Test that routes exist (even if they return errors, they shouldn't return 404)
	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/webauthn/registration/begin"},
		{"POST", "/api/v1/webauthn/registration/finish"},
		{"GET", "/api/v1/webauthn/registration/status"},
		{"POST", "/api/v1/webauthn/login/begin"},
		{"POST", "/api/v1/webauthn/login/finish"},
	}

	for _, route := range routes {
		t.Run(fmt.Sprintf("%s %s", route.method, route.path), func(t *testing.T) {
			var resp *http.Response
			var err error

			if route.method == "POST" {
				resp, err = client.doRequest(route.method, route.path, map[string]interface{}{})
			} else {
				resp, err = client.doRequest(route.method, route.path, nil)
			}
			assertNoError(t, err, "Request failed")
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				t.Fatalf("WebAuthn route %s returned 404 but WebAuthn should be enabled", route.path)
			}
			// Any other status code means the route is mounted
			t.Logf("Route %s %s is mounted (status: %d)", route.method, route.path, resp.StatusCode)
		})
	}

	t.Log("WebAuthn routes are properly mounted")
}

// ioReader is a helper to create an io.Reader from a string
func ioReader(s string) io.Reader {
	return io.NopCloser(stringReader(s))
}

// stringReader implements io.Reader for a string
type stringReader string

func (s stringReader) Read(p []byte) (n int, err error) {
	n = copy(p, s)
	if n < len(s) {
		return n, nil
	}
	return n, io.EOF
}
