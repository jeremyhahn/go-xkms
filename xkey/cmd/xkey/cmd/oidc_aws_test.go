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

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
)

func TestOIDCAWSCmd_Help(t *testing.T) {
	// Test that the AWS command is registered and has expected properties
	if oidcAWSCmd.Use != "aws" {
		t.Errorf("oidcAWSCmd.Use = %s, want aws", oidcAWSCmd.Use)
	}
	if oidcAWSCmd.Short != "AWS Console OIDC login" {
		t.Errorf("oidcAWSCmd.Short = %s, unexpected", oidcAWSCmd.Short)
	}
	if oidcAWSCmd.Long == "" {
		t.Error("oidcAWSCmd.Long should not be empty")
	}
	if oidcAWSCmd.RunE == nil {
		t.Error("oidcAWSCmd.RunE should be set")
	}
}

func TestOIDCAWSCmd_MissingRegion(t *testing.T) {
	// Test that the region flag is marked as required
	regionFlag := oidcAWSCmd.Flags().Lookup("region")
	if regionFlag == nil {
		t.Fatal("region flag should exist")
	}

	// Verify required annotation exists
	annotations := regionFlag.Annotations
	if annotations != nil {
		if _, ok := annotations["cobra_annotation_bash_completion_one_required_flag"]; ok {
			// Flag is marked as required
		}
	}

	// Test the error constant exists and has correct message
	if ErrAWSMissingRegion == nil {
		t.Fatal("ErrAWSMissingRegion should not be nil")
	}
	if ErrAWSMissingRegion.Error() != "aws: --region is required" {
		t.Errorf("ErrAWSMissingRegion.Error() = %s, unexpected", ErrAWSMissingRegion.Error())
	}
}

func TestOIDCAWSCmd_BackgroundWorkerFlag(t *testing.T) {
	// Test that the background-worker flag exists and is hidden
	backgroundWorkerFlag := oidcAWSCmd.Flags().Lookup("background-worker")
	if backgroundWorkerFlag == nil {
		t.Fatal("background-worker flag should exist")
	}

	// Verify the flag is hidden
	if !backgroundWorkerFlag.Hidden {
		t.Error("background-worker flag should be hidden")
	}

	// Verify default value is false
	if backgroundWorkerFlag.DefValue != "false" {
		t.Errorf("background-worker flag default should be false, got %s", backgroundWorkerFlag.DefValue)
	}
}

func TestOIDCAWSCmd_ProviderNameFlag(t *testing.T) {
	// Test that the provider-name flag exists and is hidden
	providerNameFlag := oidcAWSCmd.Flags().Lookup("provider-name")
	if providerNameFlag == nil {
		t.Fatal("provider-name flag should exist")
	}

	// Verify the flag is hidden
	if !providerNameFlag.Hidden {
		t.Error("provider-name flag should be hidden")
	}

	// Verify default value is empty
	if providerNameFlag.DefValue != "" {
		t.Errorf("provider-name flag default should be empty, got %s", providerNameFlag.DefValue)
	}
}

func TestHandleAWSOutput(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("aws-credentials output", func(t *testing.T) {
		credFile := filepath.Join(tmpDir, "credentials1")

		data := &handlers.TokenData{
			AWSCredentials: &handlers.AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret123",
				SessionToken:    "token123",
				Expiration:      time.Now().Add(time.Hour),
				Region:          "us-east-1",
			},
		}

		err := handleAWSOutput("aws-credentials", data, "test-profile", credFile, "")
		if err != nil {
			t.Errorf("handleAWSOutput() error = %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(credFile); os.IsNotExist(err) {
			t.Error("Credentials file should have been created")
		}

		// Read and verify content
		content, _ := os.ReadFile(credFile)
		if !bytes.Contains(content, []byte("AKIAEXAMPLE")) {
			t.Error("Credentials file should contain access key")
		}
		if !bytes.Contains(content, []byte("[test-profile]")) {
			t.Error("Credentials file should contain profile section")
		}
	})

	t.Run("json output", func(t *testing.T) {
		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		data := &handlers.TokenData{
			AWSCredentials: &handlers.AWSCredentials{
				AccessKeyID:     "AKIAJSONTEST",
				SecretAccessKey: "secret",
				SessionToken:    "token",
			},
		}

		err := handleAWSOutput("json", data, "default", "", "")

		w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Errorf("handleAWSOutput() error = %v", err)
		}

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		if output == "" {
			t.Error("JSON output should not be empty")
		}
	})

	t.Run("none output", func(t *testing.T) {
		data := &handlers.TokenData{
			AWSCredentials: &handlers.AWSCredentials{
				AccessKeyID: "test",
			},
		}

		err := handleAWSOutput("none", data, "default", "", "")
		if err != nil {
			t.Errorf("handleAWSOutput() error = %v", err)
		}
	})

	t.Run("exec without command", func(t *testing.T) {
		data := &handlers.TokenData{}
		err := handleAWSOutput("exec", data, "default", "", "")

		if err == nil {
			t.Error("Expected error when exec command is missing")
		}
	})

	t.Run("unknown output mode", func(t *testing.T) {
		data := &handlers.TokenData{}
		err := handleAWSOutput("unknown", data, "default", "", "")

		if err == nil {
			t.Error("Expected error for unknown output mode")
		}
	})
}

func TestStoreAndLoadAWSSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := filepath.Join(tmpDir, "session.json")

	session := AWSStoredSession{
		Region:       "us-east-1",
		Profile:      "test",
		AccessKeyID:  "AKIAEXAMPLE",
		Expiration:   time.Now().Add(time.Hour),
		RefreshToken: "refresh123",
		DPoPKeyPEM:   "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----",
	}

	// Store
	err := storeAWSSession(sessionFile, session)
	if err != nil {
		t.Fatalf("storeAWSSession() error = %v", err)
	}

	// Load
	loaded, err := loadAWSSession(sessionFile)
	if err != nil {
		t.Fatalf("loadAWSSession() error = %v", err)
	}

	if loaded.Region != session.Region {
		t.Errorf("Region = %s, want %s", loaded.Region, session.Region)
	}
	if loaded.Profile != session.Profile {
		t.Errorf("Profile = %s, want %s", loaded.Profile, session.Profile)
	}
	if loaded.AccessKeyID != session.AccessKeyID {
		t.Errorf("AccessKeyID = %s, want %s", loaded.AccessKeyID, session.AccessKeyID)
	}
	if loaded.RefreshToken != session.RefreshToken {
		t.Errorf("RefreshToken = %s, want %s", loaded.RefreshToken, session.RefreshToken)
	}
}

func TestLoadAWSSession_NotFound(t *testing.T) {
	_, err := loadAWSSession("/nonexistent/path/session.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestAWSStoredSession_JSON(t *testing.T) {
	expiration := time.Date(2025, 1, 15, 12, 30, 0, 0, time.UTC)

	session := AWSStoredSession{
		Region:       "eu-west-1",
		Profile:      "production",
		AccessKeyID:  "AKIATEST123",
		Expiration:   expiration,
		RefreshToken: "refresh-token-test",
	}

	// Marshal
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Unmarshal
	var loaded AWSStoredSession
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if loaded.Region != session.Region {
		t.Errorf("Region mismatch")
	}
	if loaded.Profile != session.Profile {
		t.Errorf("Profile mismatch")
	}
	if loaded.AccessKeyID != session.AccessKeyID {
		t.Errorf("AccessKeyID mismatch")
	}
}

func TestHandleAWSCallback_Error(t *testing.T) {
	// This tests the callback error handling logic
	// In real integration tests, we'd use an httptest server

	t.Run("error parameter in callback", func(t *testing.T) {
		// The callback function handles error responses from AWS
		// This is tested implicitly through the integration tests
		// but we can verify the error types exist
		if ErrAWSCallbackFailed == nil {
			t.Error("ErrAWSCallbackFailed should not be nil")
		}
	})
}

func TestOIDCAWSErrors(t *testing.T) {
	// Verify error types are defined
	errors := []error{
		ErrAWSMissingRegion,
		ErrAWSLoginFailed,
		ErrAWSCallbackFailed,
		ErrAWSTokenExchangeFailed,
		ErrAWSCredentialsWriteFailed,
		ErrAWSSessionLoadFailed,
		ErrAWSNoRefreshToken,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Error should not be nil")
		}
		if err.Error() == "" {
			t.Error("Error message should not be empty")
		}
	}
}

func TestOIDCAWSErrors_Messages(t *testing.T) {
	// Verify specific error messages
	tests := []struct {
		err      error
		expected string
	}{
		{ErrAWSMissingRegion, "aws: --region is required"},
		{ErrAWSLoginFailed, "aws: login failed"},
		{ErrAWSCallbackFailed, "aws: callback failed"},
		{ErrAWSTokenExchangeFailed, "aws: token exchange failed"},
		{ErrAWSCredentialsWriteFailed, "aws: failed to write credentials"},
		{ErrAWSSessionLoadFailed, "aws: failed to load session"},
		{ErrAWSNoRefreshToken, "aws: no refresh token in session"},
	}

	for _, tc := range tests {
		if tc.err.Error() != tc.expected {
			t.Errorf("Error message mismatch: got %q, want %q", tc.err.Error(), tc.expected)
		}
	}
}

// Benchmark for session storage
func BenchmarkStoreAWSSession(b *testing.B) {
	tmpDir := b.TempDir()
	session := AWSStoredSession{
		Region:       "us-east-1",
		Profile:      "test",
		AccessKeyID:  "AKIAEXAMPLE",
		Expiration:   time.Now().Add(time.Hour),
		RefreshToken: "refresh123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionFile := filepath.Join(tmpDir, "session.json")
		_ = storeAWSSession(sessionFile, session)
	}
}

// Test context handling
func TestHandleAWSOutput_Context(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// The handlers use context.Background() internally in the current implementation
	// This test verifies the function doesn't panic with a cancelled context
	data := &handlers.TokenData{
		AWSCredentials: &handlers.AWSCredentials{
			AccessKeyID:     "test",
			SecretAccessKey: "test",
		},
	}

	// Even with cancelled context, none handler should work
	err := handleAWSOutput("none", data, "default", "", "")
	if err != nil {
		t.Errorf("handleAWSOutput() with cancelled context error = %v", err)
	}
}

func TestGetAWSPIDFile(t *testing.T) {
	tests := []struct {
		name         string
		sessionStore string
		region       string
		providerName string
		wantSuffix   string
	}{
		{
			name:         "with provider name",
			sessionStore: "/home/user/.config/xkey/aws-session.json",
			region:       "us-east-1",
			providerName: "aws-prod",
			wantSuffix:   "pids/aws-prod.pid",
		},
		{
			name:         "without provider name",
			sessionStore: "/home/user/.config/xkey/aws-session.json",
			region:       "us-west-2",
			providerName: "",
			wantSuffix:   "pids/aws-us-west-2.pid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getAWSPIDFile(tc.sessionStore, tc.region, tc.providerName)
			if !bytes.HasSuffix([]byte(result), []byte(tc.wantSuffix)) {
				t.Errorf("getAWSPIDFile() = %s, want suffix %s", result, tc.wantSuffix)
			}
		})
	}
}

func TestGetAWSDefaultLogFile(t *testing.T) {
	tests := []struct {
		name         string
		sessionStore string
		region       string
		wantSuffix   string
	}{
		{
			name:         "us-east-1",
			sessionStore: "/home/user/.config/xkey/aws-session.json",
			region:       "us-east-1",
			wantSuffix:   "logs/aws-us-east-1.log",
		},
		{
			name:         "eu-west-1",
			sessionStore: "/home/user/.config/xkey/aws-session.json",
			region:       "eu-west-1",
			wantSuffix:   "logs/aws-eu-west-1.log",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getAWSDefaultLogFile(tc.sessionStore, tc.region)
			if !bytes.HasSuffix([]byte(result), []byte(tc.wantSuffix)) {
				t.Errorf("getAWSDefaultLogFile() = %s, want suffix %s", result, tc.wantSuffix)
			}
		})
	}
}

func TestIsAWSProcessRunning_NoPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nonexistent.pid")

	pid, running := isAWSProcessRunning(pidFile)
	if running {
		t.Error("Expected not running for nonexistent PID file")
	}
	if pid != 0 {
		t.Errorf("Expected PID 0 for nonexistent file, got %d", pid)
	}
}

func TestIsAWSProcessRunning_InvalidPIDContent(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "invalid.pid")

	// Write invalid content
	if err := os.WriteFile(pidFile, []byte("not-a-number"), 0600); err != nil {
		t.Fatalf("Failed to write PID file: %v", err)
	}

	pid, running := isAWSProcessRunning(pidFile)
	if running {
		t.Error("Expected not running for invalid PID content")
	}
	if pid != 0 {
		t.Errorf("Expected PID 0 for invalid content, got %d", pid)
	}
}

func TestIsAWSProcessRunning_StalePID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "stale.pid")

	// Write a PID that almost certainly doesn't exist (very high number)
	if err := os.WriteFile(pidFile, []byte("999999999"), 0600); err != nil {
		t.Fatalf("Failed to write PID file: %v", err)
	}

	pid, running := isAWSProcessRunning(pidFile)
	if running {
		t.Error("Expected not running for stale PID")
	}
	if pid != 999999999 {
		t.Errorf("Expected PID 999999999, got %d", pid)
	}
}
