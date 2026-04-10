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
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewExecHandler(t *testing.T) {
	handler := NewExecHandler("echo test")

	if handler.Command != "echo test" {
		t.Errorf("Command = %s, want 'echo test'", handler.Command)
	}
	if handler.Shell != "/bin/sh" {
		t.Errorf("Shell = %s, want /bin/sh", handler.Shell)
	}
	if handler.Name() != "exec" {
		t.Errorf("Name() = %s, want exec", handler.Name())
	}
}

func TestExecHandler_Handle(t *testing.T) {
	t.Run("simple command", func(t *testing.T) {
		var stdout bytes.Buffer
		handler := NewExecHandler("echo hello").WithStdout(&stdout)

		err := handler.Handle(context.Background(), &TokenData{AccessToken: "test"})
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		if got := strings.TrimSpace(stdout.String()); got != "hello" {
			t.Errorf("stdout = %q, want 'hello'", got)
		}
	})

	t.Run("nil token data", func(t *testing.T) {
		handler := NewExecHandler("echo test")
		err := handler.Handle(context.Background(), nil)

		if !errors.Is(err, ErrNilTokenResponse) {
			t.Errorf("Handle() error = %v, want ErrNilTokenResponse", err)
		}
	})

	t.Run("empty command", func(t *testing.T) {
		handler := NewExecHandler("")
		err := handler.Handle(context.Background(), &TokenData{})

		if !errors.Is(err, ErrExecCommandRequired) {
			t.Errorf("Handle() error = %v, want ErrExecCommandRequired", err)
		}
	})

	t.Run("command with OIDC env vars", func(t *testing.T) {
		var stdout bytes.Buffer
		handler := NewExecHandler("echo $OIDC_ACCESS_TOKEN").WithStdout(&stdout)

		data := &TokenData{
			AccessToken: "my-access-token",
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		if got := strings.TrimSpace(stdout.String()); got != "my-access-token" {
			t.Errorf("stdout = %q, want 'my-access-token'", got)
		}
	})

	t.Run("command with AWS env vars", func(t *testing.T) {
		var stdout bytes.Buffer
		handler := NewExecHandler("echo $AWS_ACCESS_KEY_ID").WithStdout(&stdout)

		data := &TokenData{
			AWSCredentials: &AWSCredentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
				Region:          "us-east-1",
			},
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		if got := strings.TrimSpace(stdout.String()); got != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("stdout = %q, want 'AKIAIOSFODNN7EXAMPLE'", got)
		}
	})

	t.Run("custom env vars", func(t *testing.T) {
		var stdout bytes.Buffer
		handler := NewExecHandler("echo $CUSTOM_VAR").
			WithStdout(&stdout).
			WithEnv("CUSTOM_VAR", "custom_value")

		err := handler.Handle(context.Background(), &TokenData{})
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		if got := strings.TrimSpace(stdout.String()); got != "custom_value" {
			t.Errorf("stdout = %q, want 'custom_value'", got)
		}
	})

	t.Run("command failure", func(t *testing.T) {
		var stderr bytes.Buffer
		handler := NewExecHandler("exit 1").WithStderr(&stderr)

		err := handler.Handle(context.Background(), &TokenData{})
		if err == nil {
			t.Error("Handle() expected error for failed command")
		}
		if !errors.Is(err, ErrExecCommandFailed) {
			t.Errorf("Handle() error = %v, want ErrExecCommandFailed", err)
		}
	})

	t.Run("pass JSON via stdin", func(t *testing.T) {
		var stdout bytes.Buffer
		// Use cat to echo stdin
		handler := NewExecHandler("cat").
			WithStdout(&stdout).
			WithPassJSON()

		data := &TokenData{
			AccessToken: "test-token",
			TokenType:   "Bearer",
		}

		err := handler.Handle(context.Background(), data)
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "test-token") {
			t.Errorf("JSON output should contain access token: %s", output)
		}
		if !strings.Contains(output, "Bearer") {
			t.Errorf("JSON output should contain token type: %s", output)
		}
	})

	t.Run("custom shell", func(t *testing.T) {
		var stdout bytes.Buffer
		handler := NewExecHandler("echo $SHELL").
			WithStdout(&stdout).
			WithShell("/bin/bash")

		// Note: This just tests that a custom shell can be set
		// The actual shell used depends on system availability
		err := handler.Handle(context.Background(), &TokenData{})
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		handler := NewExecHandler("sleep 10")
		err := handler.Handle(ctx, &TokenData{})

		// Should fail due to cancelled context
		if err == nil {
			t.Error("Handle() expected error for cancelled context")
		}
	})
}

func TestExecHandler_tokenEnvVars(t *testing.T) {
	handler := NewExecHandler("test")

	now := time.Now()
	data := &TokenData{
		AccessToken:  "access123",
		RefreshToken: "refresh456",
		IDToken:      "id789",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Expiry:       now,
		Scope:        "openid",
		AWSCredentials: &AWSCredentials{
			AccessKeyID:     "AKIAEXAMPLE",
			SecretAccessKey: "secret",
			SessionToken:    "session",
			Region:          "us-west-2",
			Expiration:      now,
		},
	}

	env := handler.tokenEnvVars(data)

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Check OIDC vars
	if envMap["OIDC_ACCESS_TOKEN"] != "access123" {
		t.Errorf("OIDC_ACCESS_TOKEN = %s, want access123", envMap["OIDC_ACCESS_TOKEN"])
	}
	if envMap["OIDC_REFRESH_TOKEN"] != "refresh456" {
		t.Errorf("OIDC_REFRESH_TOKEN = %s, want refresh456", envMap["OIDC_REFRESH_TOKEN"])
	}
	if envMap["OIDC_ID_TOKEN"] != "id789" {
		t.Errorf("OIDC_ID_TOKEN = %s, want id789", envMap["OIDC_ID_TOKEN"])
	}
	if envMap["OIDC_TOKEN_TYPE"] != "Bearer" {
		t.Errorf("OIDC_TOKEN_TYPE = %s, want Bearer", envMap["OIDC_TOKEN_TYPE"])
	}
	if envMap["OIDC_EXPIRES_IN"] != "3600" {
		t.Errorf("OIDC_EXPIRES_IN = %s, want 3600", envMap["OIDC_EXPIRES_IN"])
	}
	if envMap["OIDC_SCOPE"] != "openid" {
		t.Errorf("OIDC_SCOPE = %s, want openid", envMap["OIDC_SCOPE"])
	}

	// Check AWS vars
	if envMap["AWS_ACCESS_KEY_ID"] != "AKIAEXAMPLE" {
		t.Errorf("AWS_ACCESS_KEY_ID = %s, want AKIAEXAMPLE", envMap["AWS_ACCESS_KEY_ID"])
	}
	if envMap["AWS_SECRET_ACCESS_KEY"] != "secret" {
		t.Errorf("AWS_SECRET_ACCESS_KEY = %s, want secret", envMap["AWS_SECRET_ACCESS_KEY"])
	}
	if envMap["AWS_SESSION_TOKEN"] != "session" {
		t.Errorf("AWS_SESSION_TOKEN = %s, want session", envMap["AWS_SESSION_TOKEN"])
	}
	if envMap["AWS_REGION"] != "us-west-2" {
		t.Errorf("AWS_REGION = %s, want us-west-2", envMap["AWS_REGION"])
	}
	if envMap["AWS_DEFAULT_REGION"] != "us-west-2" {
		t.Errorf("AWS_DEFAULT_REGION = %s, want us-west-2", envMap["AWS_DEFAULT_REGION"])
	}
}

func TestExecHandler_Fluent(t *testing.T) {
	var stdout, stderr bytes.Buffer

	handler := NewExecHandler("echo test").
		WithShell("/bin/bash").
		WithEnv("KEY1", "value1").
		WithEnv("KEY2", "value2").
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithPassJSON()

	if handler.Shell != "/bin/bash" {
		t.Errorf("Shell = %s, want /bin/bash", handler.Shell)
	}
	if handler.Env["KEY1"] != "value1" {
		t.Errorf("Env[KEY1] = %s, want value1", handler.Env["KEY1"])
	}
	if handler.Env["KEY2"] != "value2" {
		t.Errorf("Env[KEY2] = %s, want value2", handler.Env["KEY2"])
	}
	if !handler.PassJSON {
		t.Error("PassJSON should be true")
	}
}
