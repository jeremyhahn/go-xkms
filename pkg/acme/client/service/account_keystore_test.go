// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

package service

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// hardwareStores are account key stores the client has no backend for: an
// account configured with one must never sign with a software key, and no
// software private key may be generated for it or written to disk
// (docs/acme-issuance/cli.md:78-79, Codex round-2 P1 on #2260).
var hardwareStores = []string{"tpm2", "pkcs11"}

// countingACMEServer counts every request so a test can assert that the
// client made no server contact.
func countingACMEServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected request", http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// assertNoPrivateKeyFiles walks root and fails on any file that holds a PEM
// private key block (PKCS#1, SEC 1 or PKCS#8).
func assertNoPrivateKeyFiles(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
			t.Errorf("private key written to disk: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

func hardwareAccountConfig(directory, store string) *AccountConfig {
	cfg := validAccountConfig()
	cfg.DirectoryURL = directory
	cfg.Key.Store = store
	return cfg
}

func TestAccountManager_Add_RejectsHardwareKeyStore(t *testing.T) {
	for _, store := range hardwareStores {
		t.Run(store, func(t *testing.T) {
			srv, hits := countingACMEServer(t)
			am := NewAccountManager(testConfig(), slog.Default())

			err := am.Add(context.Background(), "hw", hardwareAccountConfig(srv.URL+"/directory", store))

			var want ErrUnsupportedAccountKeyStore
			if !errors.As(err, &want) {
				t.Fatalf("Add with key store %q: err = %v, want ErrUnsupportedAccountKeyStore", store, err)
			}
			if want.Store != store {
				t.Errorf("error store = %q, want %q", want.Store, store)
			}
			if _, getErr := am.Get("hw"); getErr == nil {
				t.Error("account with an unsupported key store was added to the configuration")
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server contacted %d times", n)
			}
		})
	}
}

// TestAccountManager_Client_RejectsHardwareKeyStore covers an account that
// reaches the manager from a configuration file (not through Add): the first
// order builds its client through Client, so Client must refuse before any
// signer is generated or any request is sent.
func TestAccountManager_Client_RejectsHardwareKeyStore(t *testing.T) {
	for _, store := range hardwareStores {
		t.Run(store, func(t *testing.T) {
			srv, hits := countingACMEServer(t)
			stateDir := t.TempDir()
			cfg := testConfig()
			cfg.Storage = StorageConfig{Backend: "local", Options: map[string]interface{}{"path": stateDir}}
			cfg.Accounts["hw"] = hardwareAccountConfig(srv.URL+"/directory", store)
			am := NewAccountManager(cfg, slog.Default())

			c, err := am.Client(context.Background(), "hw")

			var want ErrUnsupportedAccountKeyStore
			if !errors.As(err, &want) {
				t.Fatalf("Client with key store %q: client = %v, err = %v, want ErrUnsupportedAccountKeyStore", store, c, err)
			}
			if c != nil {
				t.Error("Client returned a client for an unsupported key store")
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server contacted %d times", n)
			}
			assertNoPrivateKeyFiles(t, stateDir)
		})
	}
}

func TestAccountManager_Client_SoftwareStoreStillWorks(t *testing.T) {
	for _, store := range []string{"software", "file"} {
		t.Run(store, func(t *testing.T) {
			cfg := testConfig()
			cfg.Storage = StorageConfig{Backend: "local", Options: map[string]interface{}{"path": t.TempDir()}}
			acct := validAccountConfig()
			acct.Key.Store = store
			cfg.Accounts["sw"] = acct
			am := NewAccountManager(cfg, slog.Default())
			if _, err := am.Client(context.Background(), "sw"); err != nil {
				t.Fatalf("Client with key store %q: %v", store, err)
			}
		})
	}
}
