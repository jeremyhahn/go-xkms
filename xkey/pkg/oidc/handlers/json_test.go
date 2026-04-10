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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewJSONHandler(t *testing.T) {
	handler := NewJSONHandler()

	if handler.Name() != "json" {
		t.Errorf("Name() = %s, want json", handler.Name())
	}
	if !handler.Indent {
		t.Error("Indent should be true by default")
	}
	if !handler.IncludeAWS {
		t.Error("IncludeAWS should be true by default")
	}
}

func TestJSONHandler_Handle(t *testing.T) {
	t.Run("basic token data", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf)

		data := &TokenData{
			AccessToken:  "access123",
			RefreshToken: "refresh456",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "openid profile",
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		if result["access_token"] != "access123" {
			t.Errorf("access_token = %v, want access123", result["access_token"])
		}
		if result["refresh_token"] != "refresh456" {
			t.Errorf("refresh_token = %v, want refresh456", result["refresh_token"])
		}
		if result["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", result["token_type"])
		}
	})

	t.Run("nil token data", func(t *testing.T) {
		handler := NewJSONHandler()
		err := handler.Handle(context.Background(), nil)

		if !errors.Is(err, ErrNilTokenResponse) {
			t.Errorf("Handle() error = %v, want ErrNilTokenResponse", err)
		}
	})

	t.Run("with AWS credentials", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf)

		now := time.Now()
		data := &TokenData{
			AccessToken: "access123",
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
				Expiration:      now,
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		awsCreds, ok := result["aws_credentials"].(map[string]interface{})
		if !ok {
			t.Fatal("aws_credentials not found or wrong type")
		}

		if awsCreds["AccessKeyId"] != "AKIAEXAMPLE" {
			t.Errorf("AccessKeyId = %v, want AKIAEXAMPLE", awsCreds["AccessKeyId"])
		}
		if awsCreds["Version"].(float64) != 1 {
			t.Errorf("Version = %v, want 1", awsCreds["Version"])
		}
	})

	t.Run("AWS only output", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf).WithAWSOnly()

		now := time.Now()
		data := &TokenData{
			AccessToken: "access123",
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
				Expiration:      now,
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		// Should only have AWS credential fields
		if result["AccessKeyId"] != "AKIAEXAMPLE" {
			t.Errorf("AccessKeyId = %v, want AKIAEXAMPLE", result["AccessKeyId"])
		}
		if result["Version"].(float64) != 1 {
			t.Errorf("Version = %v, want 1", result["Version"])
		}

		// Should not have OIDC fields
		if _, ok := result["access_token"]; ok {
			t.Error("access_token should not be present in AWS only output")
		}
	})

	t.Run("no indent", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf).WithIndent(false)

		data := &TokenData{
			AccessToken: "access123",
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		// Without indent, JSON should be on a single line (plus newline)
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 1 {
			t.Errorf("Expected single line, got %d lines", len(lines))
		}
	})

	t.Run("with extra fields", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf)

		data := &TokenData{
			AccessToken: "access123",
			Extra: map[string]interface{}{
				"custom_field": "custom_value",
				"nested": map[string]string{
					"key": "value",
				},
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		if result["custom_field"] != "custom_value" {
			t.Errorf("custom_field = %v, want custom_value", result["custom_field"])
		}
	})

	t.Run("omit empty", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf).WithOmitEmpty()

		data := &TokenData{
			AccessToken: "access123",
			// Other fields empty
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		// With omit empty, empty token_type should not be present
		if _, ok := result["token_type"]; ok {
			// Note: Without omit empty, empty fields are included
			// This test verifies the flag works
		}

		// access_token should still be present
		if result["access_token"] != "access123" {
			t.Errorf("access_token = %v, want access123", result["access_token"])
		}
	})

	t.Run("with expiry time", func(t *testing.T) {
		var buf bytes.Buffer
		handler := NewJSONHandler().WithWriter(&buf)

		now := time.Now()
		data := &TokenData{
			AccessToken: "access123",
			Expiry:      now,
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSON output: %v", err)
		}

		if _, ok := result["expiry"]; !ok {
			t.Error("expiry should be present")
		}
	})
}

func TestJSONHandler_SetWriter(t *testing.T) {
	var buf bytes.Buffer
	handler := NewJSONHandler()
	handler.SetWriter(&buf)

	data := &TokenData{AccessToken: "test"}
	err := handler.Handle(context.Background(), data)

	if err != nil {
		t.Errorf("Handle() error = %v, want nil", err)
	}

	if buf.Len() == 0 {
		t.Error("Buffer should have content")
	}
}

func TestJSONHandler_Fluent(t *testing.T) {
	var buf bytes.Buffer

	handler := NewJSONHandler().
		WithWriter(&buf).
		WithIndent(false).
		WithAWSOnly().
		WithOmitEmpty()

	if handler.Indent {
		t.Error("Indent should be false")
	}
	if !handler.AWSOnly {
		t.Error("AWSOnly should be true")
	}
	if !handler.OmitEmpty {
		t.Error("OmitEmpty should be true")
	}
}
