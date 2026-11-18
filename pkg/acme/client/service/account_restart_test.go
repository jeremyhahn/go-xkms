package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"
)

// keyedACMEServer answers newAccount like RFC 8555 §7.3: a new JWK gets a
// new account URL (201), a known JWK gets its existing URL back (200).
func keyedACMEServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		srv   *httptest.Server
		mu    sync.Mutex
		urls  = map[string]string{}
		next  atomic.Int32
		nonce atomic.Int64
	)
	setNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonce.Add(1)))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce": srv.URL + "/new-nonce", "newAccount": srv.URL + "/new-account",
			"newOrder": srv.URL + "/new-order", "revokeCert": srv.URL + "/revoke-cert", "keyChange": srv.URL + "/key-change",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		setNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var jws struct {
			Protected string `json:"protected"`
		}
		_ = json.Unmarshal(body, &jws)
		hdr, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
		var protected struct {
			JWK json.RawMessage `json:"jwk"`
		}
		_ = json.Unmarshal(hdr, &protected)
		sum := sha256.Sum256(protected.JWK)
		thumb := string(sum[:])
		mu.Lock()
		u, known := urls[thumb]
		if !known {
			u = fmt.Sprintf("%s/account/%d", srv.URL, next.Add(1))
			urls[thumb] = u
		}
		mu.Unlock()
		setNonce(w)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", u)
		if known {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid", "orders": u + "/orders"})
	})
	mux.HandleFunc("/account/", func(w http.ResponseWriter, r *http.Request) {
		setNonce(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid", "orders": srv.URL + r.URL.Path + "/orders"})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// loadSavedConfig reads path the way a fresh process does.
func loadSavedConfig(t *testing.T, path string) *Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	cfg.ConfigFile = path
	return cfg
}

// TestRegister_RestartReusesTheAccountKeyAndURL pins that a registered
// account survives a restart: the private signer is kept (by a key file the
// config references, mode 0600) and reloaded, so the next process signs with
// the same key and the server returns the same account URL.
func TestRegister_RestartReusesTheAccountKeyAndURL(t *testing.T) {
	srv := keyedACMEServer(t)
	path := filepath.Join(t.TempDir(), "acme-client.yaml")
	if err := os.WriteFile(path, []byte("storage:\n  backend: memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	first := loadSavedConfig(t, path)
	first.Accounts = map[string]*AccountConfig{}
	am := NewAccountManager(first, testLogger())
	if err := am.Add(ctx, "board", &AccountConfig{
		DirectoryURL: srv.URL + "/directory", Email: "dev@example.com",
		Key: &KeyConfig{Algorithm: "ECDSA", Store: "software", ECC: &ECCConfig{Curve: "P-256"}},
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	acct, err := am.Register(ctx, "board")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	firstURL := acct.AccountURL
	c1, err := am.Client(ctx, "board")
	if err != nil {
		t.Fatal(err)
	}
	firstPub := c1.AccountSigner().Public()

	// A fresh process reads the saved file.
	second := loadSavedConfig(t, path)
	saved := second.Accounts["board"]
	if saved == nil || saved.AccountURL != firstURL {
		t.Fatalf("saved account = %+v, want account_url %s", saved, firstURL)
	}
	var raw struct {
		Accounts map[string]struct {
			Key struct {
				File string `yaml:"file"`
			} `yaml:"key"`
		} `yaml:"accounts"`
	}
	rawBytes, _ := os.ReadFile(path)
	_ = yaml.Unmarshal(rawBytes, &raw)
	keyFile := raw.Accounts["board"].Key.File
	if keyFile == "" {
		t.Fatalf("saved account has no key.file reference:\n%s", rawBytes)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("account key file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("account key file mode = %o, want 600", mode)
	}

	am2 := NewAccountManager(second, testLogger())
	c2, err := am2.Client(ctx, "board")
	if err != nil {
		t.Fatalf("Client after restart: %v", err)
	}
	if !reflect.DeepEqual(c2.AccountSigner().Public(), firstPub) {
		t.Fatal("after restart the account signs with a new key, want the registered one")
	}
	again, err := c2.RegisterAccount()
	if err != nil {
		t.Fatalf("authenticate after restart: %v", err)
	}
	if again.URI != firstURL {
		t.Errorf("after restart the server knows the client as %s, want %s", again.URI, firstURL)
	}
}
