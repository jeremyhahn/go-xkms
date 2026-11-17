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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/viper"
)

// fakeACMEServer serves the RFC 8555 directory, new-nonce and new-account
// resources and counts the new-account requests it receives.
func fakeACMEServer(t *testing.T, newAccounts *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	var nonce atomic.Int64
	setNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", "nonce-"+string(rune('a'+nonce.Add(1)%26)))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/new-nonce",
			"newAccount": srv.URL + "/new-account",
			"newOrder":   srv.URL + "/new-order",
			"revokeCert": srv.URL + "/revoke-cert",
			"keyChange":  srv.URL + "/key-change",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		setNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		newAccounts.Add(1)
		setNonce(w)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", srv.URL+"/account/42")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "valid",
			"contact": []string{"mailto:admin@example.com"},
			"orders":  srv.URL + "/account/42/orders",
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// loadTestConfig resets viper and reads the given config file the way the
// CLI does before a sub-command runs.
func loadTestConfig(t *testing.T, path string) {
	t.Helper()
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	if err := loadConfigFile(path); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}
}

// TestAccountAddCmd_RegistersAndPersists runs `account add` against an ACME
// server and asserts the account was registered (new-account request) and
// saved, so a later `account show` finds it with its account URL.
func TestAccountAddCmd_RegistersAndPersists(t *testing.T) {
	var newAccounts atomic.Int32
	srv := fakeACMEServer(t, &newAccounts)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trusted-acme.yaml")
	cfg := "logging:\n  level: info\n  format: text\n  output: stdout\nstorage:\n  backend: memory\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(viper.Reset)

	loadTestConfig(t, cfgPath)
	resetAccountAddFlags(t)
	add := accountAddCmd
	add.SetContext(context.Background())
	addOut := &bytes.Buffer{}
	add.SetOut(addOut)
	add.SetErr(addOut)
	for flag, val := range map[string]string{
		"directory":     srv.URL + "/directory",
		"email":         "admin@example.com",
		"key-algorithm": "ECDSA",
		"key-store":     "software",
		"key-curve":     "P-256",
	} {
		if err := add.Flags().Set(flag, val); err != nil {
			t.Fatalf("set --%s: %v", flag, err)
		}
	}
	if err := add.RunE(add, []string{"board"}); err != nil {
		t.Fatalf("account add: %v (output %q)", err, addOut.String())
	}
	if got := newAccounts.Load(); got != 1 {
		t.Fatalf("server saw %d new-account requests, want 1", got)
	}

	// A fresh process: read the config file again and show the account.
	loadTestConfig(t, cfgPath)
	show := accountShowCmd
	show.SetContext(context.Background())
	showOut := &bytes.Buffer{}
	show.SetOut(showOut)
	show.SetErr(showOut)
	if err := show.RunE(show, []string{"board"}); err != nil {
		t.Fatalf("account show after add: %v", err)
	}
	out := showOut.String()
	if !strings.Contains(out, srv.URL+"/account/42") {
		t.Errorf("account show: want account URL %s, got %q", srv.URL+"/account/42", out)
	}
	if !strings.Contains(out, srv.URL+"/directory") {
		t.Errorf("account show: want directory URL, got %q", out)
	}
}

// TestAccountAddCmd_ServerErrorIsReturned asserts a server rejection is
// returned and never printed as success, and the account is not saved.
func TestAccountAddCmd_ServerErrorIsReturned(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   srv.URL + "/new-nonce",
			"newAccount": srv.URL + "/new-account",
			"newOrder":   srv.URL + "/new-order",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n1")
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "n2")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:unauthorized","detail":"denied"}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trusted-acme.yaml")
	if err := os.WriteFile(cfgPath, []byte("storage:\n  backend: memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(viper.Reset)

	loadTestConfig(t, cfgPath)
	resetAccountAddFlags(t)
	add := accountAddCmd
	add.SetContext(context.Background())
	out := &bytes.Buffer{}
	add.SetOut(out)
	add.SetErr(out)
	for flag, val := range map[string]string{
		"directory": srv.URL + "/directory",
		"email":     "admin@example.com",
	} {
		if err := add.Flags().Set(flag, val); err != nil {
			t.Fatalf("set --%s: %v", flag, err)
		}
	}
	if err := add.RunE(add, []string{"denied"}); err == nil {
		t.Fatal("account add: want the server's error, got nil")
	}
	if strings.Contains(out.String(), "successfully") {
		t.Errorf("account add printed success after a server error: %q", out.String())
	}

	loadTestConfig(t, cfgPath)
	show := accountShowCmd
	show.SetContext(context.Background())
	show.SetOut(&bytes.Buffer{})
	if err := show.RunE(show, []string{"denied"}); err == nil {
		t.Error("account show: a rejected account must not be saved")
	}
}
