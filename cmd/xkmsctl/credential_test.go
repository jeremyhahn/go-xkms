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

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCredentialCmd_SubcommandRegistration(t *testing.T) {
	subcommands := credentialCmd.Commands()
	expected := map[string]bool{
		"submit":   false,
		"strategy": false,
	}

	for _, cmd := range subcommands {
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected subcommand %q not found on credentialCmd", name)
		}
	}
}

func TestCredentialSubmitCmd_Flags(t *testing.T) {
	flags := []string{"name", "value"}
	for _, name := range flags {
		f := credentialSubmitCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag --%s on credential submit command", name)
		}
	}
}

func TestRunCredentialSubmit_NoServer(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = &Config{Server: ""}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "secret123")

	err := runCredentialSubmit(&cmd, nil)
	if !errors.Is(err, ErrServerRequired) {
		t.Fatalf("expected ErrServerRequired, got: %v", err)
	}
}

func TestRunCredentialSubmit_NoName(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = &Config{Server: "https://localhost:8443"}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "")
	_ = cmd.Flags().Set("value", "")

	err := runCredentialSubmit(&cmd, nil)
	if !errors.Is(err, ErrCredentialNameRequired) {
		t.Fatalf("expected ErrCredentialNameRequired, got: %v", err)
	}
}

func TestRunCredentialSubmit_NoValue(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = &Config{Server: "https://localhost:8443"}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "")

	err := runCredentialSubmit(&cmd, nil)
	if !errors.Is(err, ErrCredentialValueRequired) {
		t.Fatalf("expected ErrCredentialValueRequired, got: %v", err)
	}
}

func TestRunCredentialSubmit_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/submit" {
			t.Errorf("expected path /api/v1/credentials/submit, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var body credentialSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if body.Name != "pkcs11-pin" {
			t.Errorf("expected name pkcs11-pin, got %s", body.Name)
		}
		if body.Value == "" {
			t.Error("expected non-empty base64-encoded value")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		TLSCert:      "/cert.pem",
		TLSKey:       "/key.pem",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "user123")

	err := runCredentialSubmit(&cmd, nil)
	if err != nil {
		t.Fatalf("runCredentialSubmit failed: %v", err)
	}
}

func TestRunCredentialSubmit_JSONOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "json",
		TLSCert:      "/cert.pem",
		TLSKey:       "/key.pem",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "user123")

	err := runCredentialSubmit(&cmd, nil)
	if err != nil {
		t.Fatalf("runCredentialSubmit JSON failed: %v", err)
	}
}

func TestRunCredentialSubmit_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"credential already submitted"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		TLSCert:      "/cert.pem",
		TLSKey:       "/key.pem",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "user123")

	err := runCredentialSubmit(&cmd, nil)
	if err == nil {
		t.Fatal("expected error for server conflict")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

func TestRunCredentialStrategy_NoServer(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	globalConfig = &Config{Server: ""}

	err := runCredentialStrategy(credentialStrategyCmd, nil)
	if !errors.Is(err, ErrServerRequired) {
		t.Fatalf("expected ErrServerRequired, got: %v", err)
	}
}

func TestRunCredentialStrategy_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/credentials/strategy" {
			t.Errorf("expected path /api/v1/credentials/strategy, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"strategy":"manual","auto_unseal":false}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		TLSCert:      "/cert.pem",
		TLSKey:       "/key.pem",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runCredentialStrategy(credentialStrategyCmd, nil)
	if err != nil {
		t.Fatalf("runCredentialStrategy failed: %v", err)
	}
}

func TestRunCredentialStrategy_JSONOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"strategy":"auto","auto_unseal":true}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "json",
		TLSCert:      "/cert.pem",
		TLSKey:       "/key.pem",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runCredentialStrategy(credentialStrategyCmd, nil)
	if err != nil {
		t.Fatalf("runCredentialStrategy JSON failed: %v", err)
	}
}

func TestRunCredentialStrategy_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal failure"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		TLSCert:      "/cert.pem",
		TLSKey:       "/key.pem",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runCredentialStrategy(credentialStrategyCmd, nil)
	if err == nil {
		t.Fatal("expected error for server 500")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

func TestRunCredentialSubmit_MTLSRequired(t *testing.T) {
	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	// Don't set initHTTPClientFactory so default path is taken
	initHTTPClientFactory = nil

	globalConfig = &Config{
		Server:  "https://localhost:8443",
		TLSCert: "", // Missing cert
		TLSKey:  "", // Missing key
	}

	cmd := *credentialSubmitCmd
	_ = cmd.Flags().Set("name", "pkcs11-pin")
	_ = cmd.Flags().Set("value", "user123")

	err := runCredentialSubmit(&cmd, nil)
	if err == nil {
		t.Fatal("expected error for missing mTLS credentials")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}
