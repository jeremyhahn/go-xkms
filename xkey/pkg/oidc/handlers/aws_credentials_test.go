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

package handlers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAWSCredentialsHandler(t *testing.T) {
	handler := NewAWSCredentialsHandler("test-profile")

	if handler.Profile != "test-profile" {
		t.Errorf("Profile = %s, want test-profile", handler.Profile)
	}
	if handler.CredentialsPath != DefaultAWSCredentialsPath {
		t.Errorf("CredentialsPath = %s, want %s", handler.CredentialsPath, DefaultAWSCredentialsPath)
	}
	if handler.Name() != "aws-credentials" {
		t.Errorf("Name() = %s, want aws-credentials", handler.Name())
	}
	if !handler.IncludeExpiration {
		t.Error("IncludeExpiration should be true by default")
	}
}

func TestAWSCredentialsHandler_Handle(t *testing.T) {
	t.Run("nil token data", func(t *testing.T) {
		handler := NewAWSCredentialsHandler("default")
		err := handler.Handle(context.Background(), nil)

		if !errors.Is(err, ErrNilTokenResponse) {
			t.Errorf("Handle() error = %v, want ErrNilTokenResponse", err)
		}
	})

	t.Run("missing AWS credentials", func(t *testing.T) {
		handler := NewAWSCredentialsHandler("default")
		err := handler.Handle(context.Background(), &TokenData{})

		if !errors.Is(err, ErrAWSResponseMissingCredentials) {
			t.Errorf("Handle() error = %v, want ErrAWSResponseMissingCredentials", err)
		}
	})

	t.Run("empty access key", func(t *testing.T) {
		handler := NewAWSCredentialsHandler("default")
		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				SecretAccessKey: "secret",
			},
		}

		err := handler.Handle(context.Background(), data)
		if !errors.Is(err, ErrAWSResponseMissingCredentials) {
			t.Errorf("Handle() error = %v, want ErrAWSResponseMissingCredentials", err)
		}
	})

	t.Run("empty profile", func(t *testing.T) {
		handler := &AWSCredentialsHandler{
			CredentialsPath: "/tmp/test",
			Profile:         "",
		}
		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
			},
		}

		err := handler.Handle(context.Background(), data)
		if !errors.Is(err, ErrAWSProfileRequired) {
			t.Errorf("Handle() error = %v, want ErrAWSProfileRequired", err)
		}
	})

	t.Run("empty credentials path", func(t *testing.T) {
		handler := &AWSCredentialsHandler{
			CredentialsPath: "",
			Profile:         "default",
		}
		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
			},
		}

		err := handler.Handle(context.Background(), data)
		if !errors.Is(err, ErrAWSCredentialsPathRequired) {
			t.Errorf("Handle() error = %v, want ErrAWSCredentialsPathRequired", err)
		}
	})

	t.Run("write new credentials file", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "credentials")

		handler := NewAWSCredentialsHandler("default").WithPath(credPath)

		now := time.Now()
		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "FwoGZXIvYXdzEBYaDkExample",
				Expiration:      now,
				Region:          "us-east-1",
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		// Read and verify the file
		content, err := os.ReadFile(credPath)
		if err != nil {
			t.Fatalf("Failed to read credentials file: %v", err)
		}

		contentStr := string(content)
		if !strings.Contains(contentStr, "[default]") {
			t.Error("Credentials file should contain [default] section")
		}
		if !strings.Contains(contentStr, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE") {
			t.Error("Credentials file should contain access key")
		}
		if !strings.Contains(contentStr, "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
			t.Error("Credentials file should contain secret key")
		}
		if !strings.Contains(contentStr, "aws_session_token = FwoGZXIvYXdzEBYaDkExample") {
			t.Error("Credentials file should contain session token")
		}
		if !strings.Contains(contentStr, "region = us-east-1") {
			t.Error("Credentials file should contain region")
		}

		// Check file permissions
		info, err := os.Stat(credPath)
		if err != nil {
			t.Fatalf("Failed to stat credentials file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("Credentials file permissions = %o, want 0600", info.Mode().Perm())
		}
	})

	t.Run("update existing profile", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "credentials")

		// Create initial file
		initialContent := `[default]
aws_access_key_id = OLD_KEY
aws_secret_access_key = OLD_SECRET

[other-profile]
aws_access_key_id = OTHER_KEY
aws_secret_access_key = OTHER_SECRET
`
		if err := os.WriteFile(credPath, []byte(initialContent), 0600); err != nil {
			t.Fatalf("Failed to write initial file: %v", err)
		}

		handler := NewAWSCredentialsHandler("default").WithPath(credPath)

		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "NEW_KEY",
				SecretAccessKey: "NEW_SECRET",
				SessionToken:    "NEW_TOKEN",
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		content, err := os.ReadFile(credPath)
		if err != nil {
			t.Fatalf("Failed to read credentials file: %v", err)
		}

		contentStr := string(content)

		// Default profile should be updated
		if !strings.Contains(contentStr, "aws_access_key_id = NEW_KEY") {
			t.Error("Default profile should have new access key")
		}

		// Other profile should be preserved
		if !strings.Contains(contentStr, "[other-profile]") {
			t.Error("Other profile should be preserved")
		}
		if !strings.Contains(contentStr, "OTHER_KEY") {
			t.Error("Other profile credentials should be preserved")
		}
	})

	t.Run("add new profile", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "credentials")

		// Create initial file
		initialContent := `[default]
aws_access_key_id = DEFAULT_KEY
aws_secret_access_key = DEFAULT_SECRET
`
		if err := os.WriteFile(credPath, []byte(initialContent), 0600); err != nil {
			t.Fatalf("Failed to write initial file: %v", err)
		}

		handler := NewAWSCredentialsHandler("new-profile").WithPath(credPath)

		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "NEW_KEY",
				SecretAccessKey: "NEW_SECRET",
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		content, err := os.ReadFile(credPath)
		if err != nil {
			t.Fatalf("Failed to read credentials file: %v", err)
		}

		contentStr := string(content)

		// Both profiles should exist
		if !strings.Contains(contentStr, "[default]") {
			t.Error("Default profile should be preserved")
		}
		if !strings.Contains(contentStr, "[new-profile]") {
			t.Error("New profile should be added")
		}
	})

	t.Run("without expiration", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "credentials")

		handler := NewAWSCredentialsHandler("default").
			WithPath(credPath).
			WithExpiration(false)

		now := time.Now()
		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				Expiration:      now,
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		content, err := os.ReadFile(credPath)
		if err != nil {
			t.Fatalf("Failed to read credentials file: %v", err)
		}

		if strings.Contains(string(content), "aws_credential_expiration") {
			t.Error("Credentials file should not contain expiration")
		}
	})

	t.Run("with region override", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "credentials")

		handler := NewAWSCredentialsHandler("default").
			WithPath(credPath).
			WithRegion("eu-west-1")

		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				Region:          "us-east-1", // This should be overridden
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		content, err := os.ReadFile(credPath)
		if err != nil {
			t.Fatalf("Failed to read credentials file: %v", err)
		}

		if !strings.Contains(string(content), "region = eu-west-1") {
			t.Error("Credentials file should contain overridden region")
		}
	})

	t.Run("creates directory if missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "subdir", "credentials")

		handler := NewAWSCredentialsHandler("default").WithPath(credPath)

		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		if _, err := os.Stat(credPath); os.IsNotExist(err) {
			t.Error("Credentials file should exist")
		}
	})
}

func TestAWSCredentialsHandler_readCredentialsFile(t *testing.T) {
	t.Run("parse multiple profiles", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, "credentials")

		content := `[default]
aws_access_key_id = KEY1
aws_secret_access_key = SECRET1

[profile-two]
aws_access_key_id = KEY2
aws_secret_access_key = SECRET2
region = us-west-2

# Comment line
[profile-three]
aws_access_key_id = KEY3
; Another comment
aws_secret_access_key = SECRET3
`
		if err := os.WriteFile(credPath, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		handler := NewAWSCredentialsHandler("default")
		sections, err := handler.readCredentialsFile(credPath)
		if err != nil {
			t.Fatalf("readCredentialsFile() error = %v", err)
		}

		if len(sections) != 3 {
			t.Errorf("Expected 3 sections, got %d", len(sections))
		}

		if sections["default"]["aws_access_key_id"] != "KEY1" {
			t.Error("Default profile key not parsed correctly")
		}

		if sections["profile-two"]["region"] != "us-west-2" {
			t.Error("Profile two region not parsed correctly")
		}

		if sections["profile-three"]["aws_secret_access_key"] != "SECRET3" {
			t.Error("Profile three secret not parsed correctly")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		handler := NewAWSCredentialsHandler("default")
		sections, err := handler.readCredentialsFile("/nonexistent/path")

		if !os.IsNotExist(err) {
			t.Errorf("Expected os.IsNotExist error, got %v", err)
		}

		// Should return empty sections
		if len(sections) != 0 {
			t.Error("Expected empty sections for nonexistent file")
		}
	})
}

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("Cannot get home dir: %v", err)
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"~/test", filepath.Join(home, "test")},
		{"~/.aws/credentials", filepath.Join(home, ".aws/credentials")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := expandPath(tt.input)
			if result != tt.expected {
				t.Errorf("expandPath(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAWSCredentialsHandler_Fluent(t *testing.T) {
	handler := NewAWSCredentialsHandler("default").
		WithPath("/custom/path").
		WithRegion("ap-southeast-1").
		WithExpiration(false)

	if handler.CredentialsPath != "/custom/path" {
		t.Errorf("CredentialsPath = %s, want /custom/path", handler.CredentialsPath)
	}
	if handler.Region != "ap-southeast-1" {
		t.Errorf("Region = %s, want ap-southeast-1", handler.Region)
	}
	if handler.IncludeExpiration {
		t.Error("IncludeExpiration should be false")
	}
}
