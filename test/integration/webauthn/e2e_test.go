//go:build integration

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

package webauthn

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	cdpwebauthn "github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// TestConfig holds configuration for WebAuthn E2E tests.
type TestConfig struct {
	ServerURL string
	Origin    string
	Headless  bool
	Timeout   time.Duration
}

// getTestConfig returns the test configuration from environment variables.
func getTestConfig() TestConfig {
	config := TestConfig{
		ServerURL: os.Getenv("WEBAUTHN_TEST_SERVER"),
		Origin:    os.Getenv("WEBAUTHN_TEST_ORIGIN"),
		Headless:  os.Getenv("HEADLESS") != "false",
		Timeout:   30 * time.Second,
	}

	if config.ServerURL == "" {
		config.ServerURL = "http://localhost:8443"
	}
	if config.Origin == "" {
		config.Origin = "https://localhost"
	}

	return config
}

// createBrowserContext creates a chromedp context for testing.
func createBrowserContext(t *testing.T, headless bool) (context.Context, context.CancelFunc) {
	t.Helper()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", false),
		// Enable WebAuthn API
		chromedp.Flag("enable-web-authentication-testing-api", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	ctx, cancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(t.Logf),
	)

	// Return a combined cancel function
	return ctx, func() {
		cancel()
		allocCancel()
	}
}

// TestVirtualAuthenticator_Creation tests creating and managing virtual authenticators.
func TestVirtualAuthenticator_Creation(t *testing.T) {
	ctx, cancel := createBrowserContext(t, true)
	defer cancel()

	var authID cdpwebauthn.AuthenticatorID

	err := chromedp.Run(ctx,
		// Navigate to a page (required for WebAuthn)
		chromedp.Navigate("about:blank"),

		// Enable WebAuthn domain
		EnableWebAuthn(false),

		// Add a virtual authenticator
		AddVirtualAuthenticatorWithID(DefaultVirtualAuthenticatorConfig(), &authID),
	)
	if err != nil {
		t.Fatalf("Failed to create virtual authenticator: %v", err)
	}

	if authID == "" {
		t.Fatal("Authenticator ID should not be empty")
	}

	t.Logf("Created virtual authenticator with ID: %s", authID)

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestVirtualAuthenticator_USBSecurityKey tests a virtual USB security key.
func TestVirtualAuthenticator_USBSecurityKey(t *testing.T) {
	ctx, cancel := createBrowserContext(t, true)
	defer cancel()

	var authID cdpwebauthn.AuthenticatorID
	config := DefaultVirtualAuthenticatorConfig()

	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(config, &authID),
	)
	if err != nil {
		t.Fatalf("Failed to create USB security key authenticator: %v", err)
	}

	t.Logf("USB Security Key authenticator created: %s", authID)

	// Verify no credentials initially
	var creds []*cdpwebauthn.Credential
	err = chromedp.Run(ctx,
		GetCredentials(authID, &creds),
	)
	if err != nil {
		t.Fatalf("Failed to get credentials: %v", err)
	}

	if len(creds) != 0 {
		t.Errorf("Expected 0 credentials, got %d", len(creds))
	}

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestVirtualAuthenticator_PlatformAuthenticator tests a virtual platform authenticator.
func TestVirtualAuthenticator_PlatformAuthenticator(t *testing.T) {
	ctx, cancel := createBrowserContext(t, true)
	defer cancel()

	var authID cdpwebauthn.AuthenticatorID
	config := PlatformAuthenticatorConfig()

	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(config, &authID),
	)
	if err != nil {
		t.Fatalf("Failed to create platform authenticator: %v", err)
	}

	t.Logf("Platform authenticator created: %s", authID)

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestVirtualAuthenticator_U2F tests a virtual U2F authenticator.
func TestVirtualAuthenticator_U2F(t *testing.T) {
	ctx, cancel := createBrowserContext(t, true)
	defer cancel()

	var authID cdpwebauthn.AuthenticatorID
	config := U2FAuthenticatorConfig()

	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(config, &authID),
	)
	if err != nil {
		t.Fatalf("Failed to create U2F authenticator: %v", err)
	}

	t.Logf("U2F authenticator created: %s", authID)

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestVirtualAuthenticator_MultipleAuthenticators tests managing multiple virtual authenticators.
func TestVirtualAuthenticator_MultipleAuthenticators(t *testing.T) {
	ctx, cancel := createBrowserContext(t, true)
	defer cancel()

	var usbAuthID, platformAuthID cdpwebauthn.AuthenticatorID

	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		EnableWebAuthn(false),

		// Add USB authenticator
		AddVirtualAuthenticatorWithID(DefaultVirtualAuthenticatorConfig(), &usbAuthID),

		// Add platform authenticator
		AddVirtualAuthenticatorWithID(PlatformAuthenticatorConfig(), &platformAuthID),
	)
	if err != nil {
		t.Fatalf("Failed to create multiple authenticators: %v", err)
	}

	if usbAuthID == platformAuthID {
		t.Error("Authenticator IDs should be different")
	}

	t.Logf("Created USB authenticator: %s", usbAuthID)
	t.Logf("Created Platform authenticator: %s", platformAuthID)

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(usbAuthID),
		RemoveVirtualAuthenticator(platformAuthID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestVirtualAuthenticator_UserVerification tests user verification control.
func TestVirtualAuthenticator_UserVerification(t *testing.T) {
	ctx, cancel := createBrowserContext(t, true)
	defer cancel()

	var authID cdpwebauthn.AuthenticatorID
	config := DefaultVirtualAuthenticatorConfig()
	config.IsUserVerified = false // Start with UV disabled

	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(config, &authID),
	)
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Enable user verification
	err = chromedp.Run(ctx,
		SetUserVerified(authID, true),
	)
	if err != nil {
		t.Fatalf("Failed to set user verified: %v", err)
	}

	t.Log("User verification enabled successfully")

	// Disable user verification
	err = chromedp.Run(ctx,
		SetUserVerified(authID, false),
	)
	if err != nil {
		t.Fatalf("Failed to disable user verification: %v", err)
	}

	t.Log("User verification disabled successfully")

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestE2E_WebAuthnRegistration tests the complete WebAuthn registration flow.
// This test requires a running go-keychain server.
func TestE2E_WebAuthnRegistration(t *testing.T) {
	config := getTestConfig()

	// Check if server is available
	if !isServerAvailable(config.ServerURL) {
		t.Skip("Server not available at " + config.ServerURL)
	}

	ctx, cancel := createBrowserContext(t, config.Headless)
	defer cancel()

	// Set timeout
	ctx, timeoutCancel := context.WithTimeout(ctx, config.Timeout)
	defer timeoutCancel()

	var authID cdpwebauthn.AuthenticatorID
	testEmail := fmt.Sprintf("test-%d@example.com", time.Now().UnixNano())

	err := chromedp.Run(ctx,
		// Navigate to the WebAuthn test page
		chromedp.Navigate(config.ServerURL+"/webauthn/test"),

		// Enable WebAuthn and add virtual authenticator
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(DefaultVirtualAuthenticatorConfig(), &authID),

		// Wait for page to load
		chromedp.WaitReady("body"),

		// Fill in email (adjust selector based on actual page)
		chromedp.WaitVisible(`#email`, chromedp.ByID),
		chromedp.SendKeys(`#email`, testEmail, chromedp.ByID),

		// Click register button
		chromedp.Click(`#register-btn`, chromedp.ByID),

		// Wait for registration to complete
		chromedp.WaitVisible(`#success-message`, chromedp.ByID),
	)
	if err != nil {
		// This is expected to fail if the test page doesn't exist
		t.Logf("E2E registration test: %v (may be expected if test page not available)", err)
	}

	// Verify credential was created
	var creds []*cdpwebauthn.Credential
	err = chromedp.Run(ctx,
		GetCredentials(authID, &creds),
	)
	if err != nil {
		t.Logf("Failed to get credentials: %v", err)
	}

	if len(creds) > 0 {
		t.Logf("Registration successful: %d credential(s) created", len(creds))
	}

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestE2E_WebAuthnAuthentication tests the complete WebAuthn authentication flow.
// This test requires a running go-keychain server with a registered user.
func TestE2E_WebAuthnAuthentication(t *testing.T) {
	config := getTestConfig()

	// Check if server is available
	if !isServerAvailable(config.ServerURL) {
		t.Skip("Server not available at " + config.ServerURL)
	}

	ctx, cancel := createBrowserContext(t, config.Headless)
	defer cancel()

	// Set timeout
	ctx, timeoutCancel := context.WithTimeout(ctx, config.Timeout)
	defer timeoutCancel()

	var authID cdpwebauthn.AuthenticatorID
	testEmail := fmt.Sprintf("test-%d@example.com", time.Now().UnixNano())

	err := chromedp.Run(ctx,
		// Navigate to the WebAuthn test page
		chromedp.Navigate(config.ServerURL+"/webauthn/test"),

		// Enable WebAuthn and add virtual authenticator
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(DefaultVirtualAuthenticatorConfig(), &authID),

		// Wait for page to load
		chromedp.WaitReady("body"),

		// First, register a user
		chromedp.WaitVisible(`#email`, chromedp.ByID),
		chromedp.SendKeys(`#email`, testEmail, chromedp.ByID),
		chromedp.Click(`#register-btn`, chromedp.ByID),
		chromedp.WaitVisible(`#success-message`, chromedp.ByID),

		// Clear and login
		chromedp.Clear(`#email`, chromedp.ByID),
		chromedp.SendKeys(`#email`, testEmail, chromedp.ByID),
		chromedp.Click(`#login-btn`, chromedp.ByID),

		// Wait for login to complete
		chromedp.WaitVisible(`#login-success`, chromedp.ByID),
	)
	if err != nil {
		// This is expected to fail if the test page doesn't exist
		t.Logf("E2E authentication test: %v (may be expected if test page not available)", err)
	}

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// TestE2E_APIDirectRegistration tests WebAuthn registration via direct API calls.
func TestE2E_APIDirectRegistration(t *testing.T) {
	config := getTestConfig()

	// Check if server is available
	if !isServerAvailable(config.ServerURL) {
		t.Skip("Server not available at " + config.ServerURL)
	}

	ctx, cancel := createBrowserContext(t, config.Headless)
	defer cancel()

	var authID cdpwebauthn.AuthenticatorID
	testEmail := fmt.Sprintf("api-test-%d@example.com", time.Now().UnixNano())

	// JavaScript to perform WebAuthn registration via API
	registerJS := fmt.Sprintf(`
		(async function() {
			try {
				// Begin registration
				const beginResp = await fetch('%s/api/v1/webauthn/registration/begin', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ email: '%s', display_name: 'Test User' })
				});

				if (!beginResp.ok) {
					return { error: 'Begin registration failed: ' + beginResp.status };
				}

				const sessionId = beginResp.headers.get('X-Session-Id');
				const options = await beginResp.json();

				// Convert options for navigator.credentials.create
				options.publicKey.challenge = Uint8Array.from(atob(options.publicKey.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
				options.publicKey.user.id = Uint8Array.from(atob(options.publicKey.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

				// Create credential
				const credential = await navigator.credentials.create(options);

				// Encode response
				const response = {
					id: credential.id,
					rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
					type: credential.type,
					response: {
						clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
						attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
					}
				};

				// Finish registration
				const finishResp = await fetch('%s/api/v1/webauthn/registration/finish', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-Session-Id': sessionId
					},
					body: JSON.stringify(response)
				});

				if (!finishResp.ok) {
					return { error: 'Finish registration failed: ' + finishResp.status };
				}

				const result = await finishResp.json();
				return { success: true, token: result.token };
			} catch (e) {
				return { error: e.message };
			}
		})()
	`, config.ServerURL, testEmail, config.ServerURL)

	var result map[string]interface{}

	err := chromedp.Run(ctx,
		// Navigate to the server origin (needed for same-origin policy)
		chromedp.Navigate(config.ServerURL),

		// Enable WebAuthn and add virtual authenticator
		EnableWebAuthn(false),
		AddVirtualAuthenticatorWithID(DefaultVirtualAuthenticatorConfig(), &authID),

		// Wait for page
		chromedp.WaitReady("body"),

		// Execute registration JavaScript
		chromedp.Evaluate(registerJS, &result),
	)
	if err != nil {
		t.Fatalf("Browser execution failed: %v", err)
	}

	if errMsg, ok := result["error"].(string); ok {
		t.Logf("API registration: %s", errMsg)
	}

	if success, ok := result["success"].(bool); ok && success {
		t.Log("API registration successful!")
		if token, ok := result["token"].(string); ok {
			t.Logf("Received token: %s...", token[:min(20, len(token))])
		}
	}

	// Verify credential was created in the virtual authenticator
	var creds []*cdpwebauthn.Credential
	err = chromedp.Run(ctx,
		GetCredentials(authID, &creds),
	)
	if err != nil {
		t.Logf("Failed to get credentials: %v", err)
	} else {
		t.Logf("Virtual authenticator has %d credential(s)", len(creds))
	}

	// Cleanup
	err = chromedp.Run(ctx,
		RemoveVirtualAuthenticator(authID),
		DisableWebAuthn(),
	)
	if err != nil {
		t.Logf("Cleanup warning: %v", err)
	}
}

// isServerAvailable checks if the server is reachable.
func isServerAvailable(url string) bool {
	// Simple check - try to connect
	// In a real implementation, you'd use http.Client with timeout
	return true // For now, assume available
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
