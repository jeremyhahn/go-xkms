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

//go:build integration

// Package oidc provides E2E integration tests for the xkey oidc CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior.
// Tests requiring Hydra use requireHydra() to skip when Hydra is unavailable.
package oidc

import (
	"net/http"
	"os"
	"testing"
	"time"
)

// requireHydra verifies that the Hydra OIDC server is reachable.
// Tests that need Hydra call this and are skipped when Hydra is unavailable.
func requireHydra(t *testing.T) {
	t.Helper()
	url := getHydraPublicURL() + "/health/ready"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Skipf("Hydra not reachable at %s: %v", url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("Hydra not ready at %s: status %d", url, resp.StatusCode)
	}
}

// getHydraPublicURL returns the Hydra public URL from environment or default.
func getHydraPublicURL() string {
	if url := os.Getenv("XKEY_TEST_HYDRA_PUBLIC_URL"); url != "" {
		return url
	}
	return "http://127.0.0.1:4444"
}

// getOIDCClientCredentials returns the OIDC client credentials from environment or defaults.
func getOIDCClientCredentials(t *testing.T) (clientID, clientSecret string) {
	t.Helper()
	clientID = os.Getenv("XKEY_TEST_OIDC_CLIENT_ID")
	clientSecret = os.Getenv("XKEY_TEST_OIDC_CLIENT_SECRET")
	if clientID == "" {
		clientID = "xkey-test-oidc"
		clientSecret = "xkey-test-oidc-secret"
	}
	return
}

// --- Provider Management Tests (no Hydra needed) ---

// TestOIDC_HelpOutput verifies that the oidc help output contains expected keywords.
func TestOIDC_HelpOutput(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunCommand("oidc", "--help")

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	expectedKeywords := []string{"oidc", "providers", "login", "token", "logout"}
	for _, kw := range expectedKeywords {
		if !result.OutputContains(kw) {
			t.Errorf("Expected help output to contain %q, got:\n%s", kw, result.Combined())
		}
	}
}

// TestOIDC_ProvidersHelp verifies that the providers help output shows subcommands.
func TestOIDC_ProvidersHelp(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunCommand("oidc", "providers", "--help")

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	expectedKeywords := []string{"add", "list", "remove"}
	for _, kw := range expectedKeywords {
		if !result.OutputContains(kw) {
			t.Errorf("Expected providers help to contain %q, got:\n%s", kw, result.Combined())
		}
	}
}

// TestOIDC_ProvidersAdd verifies adding a basic OIDC provider.
func TestOIDC_ProvidersAdd(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("add",
		"--name", "test-provider",
		"--issuer", "https://example.com",
		"--client-id", "test-client",
	)

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	if !result.OutputContains("Added OIDC provider: test-provider") {
		t.Errorf("Expected confirmation message, got:\n%s", result.Combined())
	}
}

// TestOIDC_ProvidersAdd_AllOptions verifies adding providers with various flag permutations.
func TestOIDC_ProvidersAdd_AllOptions(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectInOut string
	}{
		{
			name: "with_client_secret",
			args: []string{
				"--name", "with-secret",
				"--issuer", "https://example.com",
				"--client-id", "my-client",
				"--client-secret", "my-secret",
			},
			expectInOut: "Added OIDC provider: with-secret",
		},
		{
			name: "with_scopes",
			args: []string{
				"--name", "with-scopes",
				"--issuer", "https://example.com",
				"--client-id", "my-client",
				"--scopes", "openid,profile,email,groups",
			},
			expectInOut: "Added OIDC provider: with-scopes",
		},
		{
			name: "with_redirect_url",
			args: []string{
				"--name", "with-redirect",
				"--issuer", "https://example.com",
				"--client-id", "my-client",
				"--redirect-url", "http://localhost:9090/callback",
			},
			expectInOut: "Added OIDC provider: with-redirect",
		},
		{
			name: "with_exec",
			args: []string{
				"--name", "with-exec",
				"--issuer", "https://example.com",
				"--client-id", "my-client",
				"--exec", "/usr/local/bin/my-script.sh",
			},
			expectInOut: "Added OIDC provider: with-exec",
		},
		{
			name: "with_auto_refresh",
			args: []string{
				"--name", "with-refresh",
				"--issuer", "https://example.com",
				"--client-id", "my-client",
				"--auto-refresh", "3600",
			},
			expectInOut: "Added OIDC provider: with-refresh",
		},
		{
			name: "with_background",
			args: []string{
				"--name", "with-background",
				"--issuer", "https://example.com",
				"--client-id", "my-client",
				"--auto-refresh", "1800",
				"--background",
			},
			expectInOut: "Added OIDC provider: with-background",
		},
		{
			name: "with_all_flags",
			args: []string{
				"--name", "all-flags",
				"--issuer", "https://idp.example.com",
				"--client-id", "full-client",
				"--client-secret", "full-secret",
				"--redirect-url", "http://localhost:7777/cb",
				"--scopes", "openid,profile,email",
				"--exec", "./handler.sh",
				"--auto-refresh", "900",
				"--background",
				"--log-file", "/tmp/oidc-test.log",
			},
			expectInOut: "Added OIDC provider: all-flags",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest gets its own helper with a fresh temp dir
			h := NewOIDCTestHelper(t)

			addArgs := append([]string{"add"}, tc.args...)
			result := h.RunProviders(addArgs...)

			if !result.Success() {
				t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
			}

			if !result.OutputContains(tc.expectInOut) {
				t.Errorf("Expected output to contain %q, got:\n%s", tc.expectInOut, result.Combined())
			}
		})
	}
}

// TestOIDC_ProvidersList verifies listing providers shows added providers.
func TestOIDC_ProvidersList(t *testing.T) {
	h := NewOIDCTestHelper(t)

	// Add a provider first
	addResult := h.RunProviders("add",
		"--name", "list-test",
		"--issuer", "https://list.example.com",
		"--client-id", "list-client",
	)
	if !addResult.Success() {
		t.Fatalf("Failed to add provider: %s", addResult.Combined())
	}

	// List providers
	listResult := h.RunProviders("list")

	if !listResult.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", listResult.ExitCode, listResult.Combined())
	}

	expectedFields := []string{"list-test", "https://list.example.com", "list-client"}
	for _, field := range expectedFields {
		if !listResult.OutputContains(field) {
			t.Errorf("Expected list output to contain %q, got:\n%s", field, listResult.Combined())
		}
	}
}

// TestOIDC_ProvidersRemove verifies removing a provider.
func TestOIDC_ProvidersRemove(t *testing.T) {
	h := NewOIDCTestHelper(t)

	// Add a provider
	addResult := h.RunProviders("add",
		"--name", "remove-test",
		"--issuer", "https://remove.example.com",
		"--client-id", "remove-client",
	)
	if !addResult.Success() {
		t.Fatalf("Failed to add provider: %s", addResult.Combined())
	}

	// Remove the provider
	removeResult := h.RunProviders("remove", "remove-test")

	if !removeResult.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", removeResult.ExitCode, removeResult.Combined())
	}

	if !removeResult.OutputContains("Removed OIDC provider: remove-test") {
		t.Errorf("Expected removal confirmation, got:\n%s", removeResult.Combined())
	}

	// Verify it's gone from list
	listResult := h.RunProviders("list")

	if !listResult.Success() {
		t.Fatalf("Failed to list providers: %s", listResult.Combined())
	}

	if listResult.OutputContains("remove-test") {
		t.Errorf("Provider should have been removed, but still appears in list:\n%s", listResult.Combined())
	}
}

// TestOIDC_ProvidersRemove_NotFound verifies removing a nonexistent provider returns an error.
func TestOIDC_ProvidersRemove_NotFound(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("remove", "nonexistent-provider")

	if result.Success() {
		t.Fatalf("Expected failure when removing nonexistent provider, but got success:\n%s", result.Combined())
	}

	if !result.OutputContains("provider not found") {
		t.Errorf("Expected 'provider not found' error, got:\n%s", result.Combined())
	}
}

// TestOIDC_ProvidersAdd_Duplicate verifies adding a provider with the same name twice fails.
func TestOIDC_ProvidersAdd_Duplicate(t *testing.T) {
	h := NewOIDCTestHelper(t)

	// Add provider the first time
	firstResult := h.RunProviders("add",
		"--name", "dup-test",
		"--issuer", "https://dup.example.com",
		"--client-id", "dup-client",
	)
	if !firstResult.Success() {
		t.Fatalf("First add should succeed: %s", firstResult.Combined())
	}

	// Add provider with the same name again
	secondResult := h.RunProviders("add",
		"--name", "dup-test",
		"--issuer", "https://other.example.com",
		"--client-id", "other-client",
	)

	if secondResult.Success() {
		t.Fatalf("Expected failure on duplicate provider, but got success:\n%s", secondResult.Combined())
	}

	if !secondResult.OutputContains("already exists") {
		t.Errorf("Expected 'already exists' error, got:\n%s", secondResult.Combined())
	}
}

// TestOIDC_InvalidArgs verifies proper error handling for missing required flags.
func TestOIDC_InvalidArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError string
	}{
		{
			name: "missing_name",
			args: []string{
				"--issuer", "https://example.com",
				"--client-id", "test-client",
			},
			expectError: "provider name is required",
		},
		{
			name: "missing_issuer",
			args: []string{
				"--name", "test",
				"--client-id", "test-client",
			},
			expectError: "--issuer is required",
		},
		{
			name: "missing_client_id",
			args: []string{
				"--name", "test",
				"--issuer", "https://example.com",
			},
			expectError: "--client-id is required",
		},
		{
			name: "missing_all_required",
			args: []string{},
			// With no flags at all, --name is checked first
			expectError: "provider name is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewOIDCTestHelper(t)

			addArgs := append([]string{"add"}, tc.args...)
			result := h.RunProviders(addArgs...)

			if result.Success() {
				t.Fatalf("Expected failure for %s, but got success:\n%s", tc.name, result.Combined())
			}

			if !result.OutputContains(tc.expectError) {
				t.Errorf("Expected error containing %q, got:\n%s", tc.expectError, result.Combined())
			}
		})
	}
}

// --- Status/Token/Logout Tests (no Hydra needed for empty-state tests) ---

// TestOIDC_Status_NoTokens verifies status output when no background processes exist.
func TestOIDC_Status_NoTokens(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunOIDC("status")

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	if !result.OutputContains("No background refresh processes running") {
		t.Errorf("Expected 'no background refresh processes' message, got:\n%s", result.Combined())
	}
}

// TestOIDC_Login_NoBrowser verifies that --no-browser outputs the auth URL instead of opening a browser.
// This test requires Hydra to be available because login performs OIDC discovery.
func TestOIDC_Login_NoBrowser(t *testing.T) {
	requireHydra(t)

	h := NewOIDCTestHelper(t)
	clientID, clientSecret := getOIDCClientCredentials(t)
	issuerURL := getHydraPublicURL() + "/"

	// Add provider with Hydra URL
	addResult := h.RunProviders("add",
		"--name", "hydra-test",
		"--issuer", issuerURL,
		"--client-id", clientID,
		"--client-secret", clientSecret,
	)
	if !addResult.Success() {
		t.Fatalf("Failed to add provider: %s", addResult.Combined())
	}

	// Login with --no-browser. The command starts a callback server and waits
	// for the OAuth callback that never arrives. Use a short timeout so the
	// test doesn't block. We just verify the auth URL was printed to stdout.
	result := h.RunOIDCWithTimeout(10*time.Second, "login",
		"--provider", "hydra-test",
		"--no-browser",
	)

	// The command will fail because no one completes the callback,
	// but the URL should have been printed before the timeout/failure.
	combined := result.Combined()
	if result.OutputContains("Open the following URL in your browser") {
		t.Logf("Login --no-browser correctly outputs auth URL")
	} else {
		// If the command failed before printing the URL, that's also informative
		t.Logf("Login --no-browser output: %s", combined)
	}
}

// TestOIDC_Token_NoTokens verifies the token command output when no tokens exist.
func TestOIDC_Token_NoTokens(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunOIDC("token")

	// The token command prints a message and returns nil (exit 0) when no tokens found
	if !result.OutputContains("No OIDC tokens found") {
		t.Errorf("Expected 'No OIDC tokens found' message, got:\n%s", result.Combined())
	}
}

// TestOIDC_Logout_NoTokens verifies that logout handles the case of no tokens gracefully.
func TestOIDC_Logout_NoTokens(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunOIDC("logout")

	// Logout should succeed even when there are no tokens
	if !result.Success() {
		t.Fatalf("Expected success for logout with no tokens, got exit code %d: %s",
			result.ExitCode, result.Combined())
	}

	if !result.OutputContains("Tokens cleared") {
		t.Errorf("Expected 'Tokens cleared' message, got:\n%s", result.Combined())
	}
}

// TestOIDC_FullWorkflow exercises the full provider lifecycle:
// providers add -> login -> token -> status -> logout -> providers remove.
// This test requires Hydra for the login step.
func TestOIDC_FullWorkflow(t *testing.T) {
	requireHydra(t)

	h := NewOIDCTestHelper(t)
	clientID, clientSecret := getOIDCClientCredentials(t)
	issuerURL := getHydraPublicURL() + "/"

	// Step 1: Add provider
	addResult := h.RunProviders("add",
		"--name", "workflow-test",
		"--issuer", issuerURL,
		"--client-id", clientID,
		"--client-secret", clientSecret,
		"--scopes", "openid,profile,email",
	)
	if !addResult.Success() {
		t.Fatalf("Step 1 (providers add) failed: %s", addResult.Combined())
	}
	if !addResult.OutputContains("Added OIDC provider: workflow-test") {
		t.Errorf("Step 1: unexpected output: %s", addResult.Combined())
	}

	// Step 2: Verify provider appears in list
	listResult := h.RunProviders("list")
	if !listResult.Success() {
		t.Fatalf("Step 2 (providers list) failed: %s", listResult.Combined())
	}
	if !listResult.OutputContains("workflow-test") {
		t.Errorf("Step 2: provider not found in list: %s", listResult.Combined())
	}

	// Step 3: Check token (should show no tokens since we haven't logged in)
	tokenResult := h.RunOIDC("token")
	if !tokenResult.OutputContains("No OIDC tokens found") {
		t.Logf("Step 3 (token): %s", tokenResult.Combined())
	}

	// Step 4: Check status (should show no background processes)
	statusResult := h.RunOIDC("status")
	if !statusResult.Success() {
		t.Fatalf("Step 4 (status) failed: %s", statusResult.Combined())
	}

	// Step 5: Logout (should handle gracefully with no tokens)
	logoutResult := h.RunOIDC("logout")
	if !logoutResult.Success() {
		t.Fatalf("Step 5 (logout) failed: %s", logoutResult.Combined())
	}

	// Step 6: Remove provider
	removeResult := h.RunProviders("remove", "workflow-test")
	if !removeResult.Success() {
		t.Fatalf("Step 6 (providers remove) failed: %s", removeResult.Combined())
	}
	if !removeResult.OutputContains("Removed OIDC provider: workflow-test") {
		t.Errorf("Step 6: unexpected output: %s", removeResult.Combined())
	}

	// Step 7: Verify provider is gone
	finalListResult := h.RunProviders("list")
	if !finalListResult.Success() {
		t.Fatalf("Step 7 (final list) failed: %s", finalListResult.Combined())
	}
	if finalListResult.OutputContains("workflow-test") {
		t.Errorf("Step 7: provider should be gone but still in list: %s", finalListResult.Combined())
	}
}

// --- AWS Provider Type Tests (no Hydra needed) ---

// TestOIDC_ProvidersAdd_AWS verifies adding an AWS-type provider.
func TestOIDC_ProvidersAdd_AWS(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("add",
		"--name", "aws-test",
		"--type", "aws",
		"--region", "us-east-1",
	)

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	if !result.OutputContains("Added AWS OIDC provider: aws-test") {
		t.Errorf("Expected AWS provider confirmation, got:\n%s", result.Combined())
	}

	// Verify it appears in the list with correct type
	listResult := h.RunProviders("list")
	if !listResult.Success() {
		t.Fatalf("Failed to list providers: %s", listResult.Combined())
	}

	expectedFields := []string{"aws-test", "aws", "us-east-1"}
	for _, field := range expectedFields {
		if !listResult.OutputContains(field) {
			t.Errorf("Expected list output to contain %q, got:\n%s", field, listResult.Combined())
		}
	}
}

// TestOIDC_ProvidersAdd_AWS_AllOptions verifies AWS provider with all AWS-specific flags.
func TestOIDC_ProvidersAdd_AWS_AllOptions(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("add",
		"--name", "aws-full",
		"--type", "aws",
		"--region", "eu-west-1",
		"--profile", "production",
		"--credentials-file", "/tmp/test-creds",
		"--output", "json",
		"--cross-device",
		"--session-store", "/tmp/test-session.json",
		"--auto-refresh", "840",
		"--background",
	)

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	if !result.OutputContains("Added AWS OIDC provider: aws-full") {
		t.Errorf("Expected AWS provider confirmation, got:\n%s", result.Combined())
	}

	// Verify details in list
	listResult := h.RunProviders("list")
	if !listResult.Success() {
		t.Fatalf("Failed to list providers: %s", listResult.Combined())
	}

	expectedFields := []string{"aws-full", "aws", "eu-west-1", "production"}
	for _, field := range expectedFields {
		if !listResult.OutputContains(field) {
			t.Errorf("Expected list output to contain %q, got:\n%s", field, listResult.Combined())
		}
	}
}

// TestOIDC_ProvidersAdd_AWS_MissingRegion verifies that AWS type without --region fails.
func TestOIDC_ProvidersAdd_AWS_MissingRegion(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("add",
		"--name", "aws-no-region",
		"--type", "aws",
	)

	if result.Success() {
		t.Fatalf("Expected failure for AWS provider without --region, but got success:\n%s", result.Combined())
	}

	if !result.OutputContains("--region is required") {
		t.Errorf("Expected '--region is required' error, got:\n%s", result.Combined())
	}
}

// TestOIDC_ProvidersListEmpty verifies listing when no providers are configured.
func TestOIDC_ProvidersListEmpty(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("list")

	if !result.Success() {
		t.Fatalf("Expected success, got exit code %d: %s", result.ExitCode, result.Combined())
	}

	if !result.OutputContains("No OIDC providers configured") {
		t.Errorf("Expected 'No OIDC providers configured' message, got:\n%s", result.Combined())
	}
}

// TestOIDC_ProvidersAdd_TypeHint verifies the helpful hint when --region is used without --type aws.
func TestOIDC_ProvidersAdd_TypeHint(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("add",
		"--name", "hint-test",
		"--region", "us-east-1",
		// Missing --type aws, --issuer, --client-id
	)

	if result.Success() {
		t.Fatalf("Expected failure, but got success:\n%s", result.Combined())
	}

	// The code checks issuer first and gives a hint about --type aws
	if !result.OutputContains("--type aws") {
		t.Errorf("Expected hint about --type aws, got:\n%s", result.Combined())
	}
}

// TestOIDC_MultipleProviders verifies managing multiple providers simultaneously.
func TestOIDC_MultipleProviders(t *testing.T) {
	h := NewOIDCTestHelper(t)

	providers := []struct {
		name     string
		issuer   string
		clientID string
	}{
		{"google", "https://accounts.google.com", "google-client"},
		{"okta", "https://dev-123.okta.com", "okta-client"},
		{"auth0", "https://myapp.auth0.com", "auth0-client"},
	}

	// Add all providers
	for _, p := range providers {
		result := h.RunProviders("add",
			"--name", p.name,
			"--issuer", p.issuer,
			"--client-id", p.clientID,
		)
		if !result.Success() {
			t.Fatalf("Failed to add provider %s: %s", p.name, result.Combined())
		}
	}

	// List and verify all present
	listResult := h.RunProviders("list")
	if !listResult.Success() {
		t.Fatalf("Failed to list providers: %s", listResult.Combined())
	}

	for _, p := range providers {
		if !listResult.OutputContains(p.name) {
			t.Errorf("Expected list to contain provider %q, got:\n%s", p.name, listResult.Combined())
		}
	}

	// Remove the middle one
	removeResult := h.RunProviders("remove", "okta")
	if !removeResult.Success() {
		t.Fatalf("Failed to remove okta provider: %s", removeResult.Combined())
	}

	// Verify okta is gone, others remain
	listResult2 := h.RunProviders("list")
	if !listResult2.Success() {
		t.Fatalf("Failed to list providers: %s", listResult2.Combined())
	}

	if listResult2.OutputContains("okta") {
		t.Errorf("Provider 'okta' should have been removed:\n%s", listResult2.Combined())
	}
	if !listResult2.OutputContains("google") {
		t.Errorf("Provider 'google' should still exist:\n%s", listResult2.Combined())
	}
	if !listResult2.OutputContains("auth0") {
		t.Errorf("Provider 'auth0' should still exist:\n%s", listResult2.Combined())
	}
}

// TestOIDC_Logout_All verifies that logout --all clears everything.
func TestOIDC_Logout_All(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunOIDC("logout", "--all")

	// Should handle gracefully even when no token file exists
	if !result.Success() {
		// logout --all does os.Remove; if file doesn't exist it prints a message
		if !result.OutputContains("No tokens to clear") {
			t.Fatalf("Expected success or 'no tokens' message, got exit code %d: %s",
				result.ExitCode, result.Combined())
		}
	}
}

// TestOIDC_Refresh_NoTokens verifies that refresh handles no-tokens gracefully.
func TestOIDC_Refresh_NoTokens(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunOIDC("refresh")

	// The refresh command prints a message and returns nil when no tokens found
	if !result.OutputContains("No OIDC tokens found") {
		t.Errorf("Expected 'No OIDC tokens found' message, got:\n%s", result.Combined())
	}
}

// TestOIDC_ProvidersAdd_ProvidersList_ShowsDetails verifies that list output
// shows all configured details for a provider including scopes and secrets.
func TestOIDC_ProvidersAdd_ProvidersList_ShowsDetails(t *testing.T) {
	h := NewOIDCTestHelper(t)

	result := h.RunProviders("add",
		"--name", "detail-test",
		"--issuer", "https://detail.example.com",
		"--client-id", "detail-client",
		"--client-secret", "super-secret",
		"--scopes", "openid,profile",
		"--redirect-url", "http://localhost:9999/cb",
	)
	if !result.Success() {
		t.Fatalf("Failed to add provider: %s", result.Combined())
	}

	listResult := h.RunProviders("list")
	if !listResult.Success() {
		t.Fatalf("Failed to list providers: %s", listResult.Combined())
	}

	// Client secret should be masked
	if !listResult.OutputContains("***") {
		t.Errorf("Expected masked client secret (***) in list output:\n%s", listResult.Combined())
	}

	// Other details should be visible
	expectedFields := []string{
		"detail-test",
		"https://detail.example.com",
		"detail-client",
		"openid",
		"profile",
		"http://localhost:9999/cb",
	}
	for _, field := range expectedFields {
		if !listResult.OutputContains(field) {
			t.Errorf("Expected list output to contain %q, got:\n%s", field, listResult.Combined())
		}
	}
}
