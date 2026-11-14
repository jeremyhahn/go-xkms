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

// credential_run_test.go closes the remaining branches in
// runCredentialSubmit / runCredentialStrategy: the doServerRequest transport
// error (unreachable server) and the JSON-decode-failure paths, neither of
// which credential_test.go's httptest-server-error case reaches.
package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunCredentialSubmit_TransportError(t *testing.T) {
	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	}()

	// Port 1 on loopback: nothing listens there, so the connection is
	// refused immediately without any real network access.
	globalConfig = &Config{Server: "http://127.0.0.1:1", OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return &http.Client{}, nil
	}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "user123")

	err := runCredentialSubmit(&cmd, nil)
	if err == nil {
		t.Fatal("expected transport error for unreachable server")
	}
}

func TestRunCredentialSubmit_MalformedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "user123")

	err := runCredentialSubmit(&cmd, nil)
	if !errors.Is(err, ErrHTTPRequestFailed) {
		t.Fatalf("expected ErrHTTPRequestFailed, got: %v", err)
	}
}

func TestRunCredentialStrategy_TransportError(t *testing.T) {
	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{Server: "http://127.0.0.1:1", OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return &http.Client{}, nil
	}

	err := runCredentialStrategy(credentialStrategyCmd, nil)
	if err == nil {
		t.Fatal("expected transport error for unreachable server")
	}
}

func TestRunCredentialStrategy_MalformedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runCredentialStrategy(credentialStrategyCmd, nil)
	if !errors.Is(err, ErrHTTPRequestFailed) {
		t.Fatalf("expected ErrHTTPRequestFailed, got: %v", err)
	}
}

// --- credential list ---

func TestRunCredentialList_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"names":["aws-kms-key","pkcs11-user-pin"]}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	out := captureStdout(t, func() {
		if err := runCredentialList(credentialListCmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, want := range []string{"pkcs11-user-pin", "aws-kms-key"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got: %q", want, out)
		}
	}
}

func TestRunCredentialList_RequiresServer(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = &Config{OutputFormat: "text"}

	if err := runCredentialList(credentialListCmd, nil); !errors.Is(err, ErrServerRequired) {
		t.Fatalf("expected ErrServerRequired, got: %v", err)
	}
}

func TestRunCredentialList_MalformedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	if err := runCredentialList(credentialListCmd, nil); !errors.Is(err, ErrHTTPRequestFailed) {
		t.Fatalf("expected ErrHTTPRequestFailed, got: %v", err)
	}
}
