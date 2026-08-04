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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// =============================================================================
// Test helpers
// =============================================================================

// resetAccountAddFlags restores accountAddCmd's flags to their registered
// defaults so tests do not leak state into one another.
func resetAccountAddFlags(t *testing.T) {
	t.Helper()
	f := accountAddCmd.Flags()
	_ = f.Set("directory", "")
	_ = f.Set("email", "")
	_ = f.Set("key-algorithm", "ECDSA")
	_ = f.Set("key-store", "software")
	_ = f.Set("key-curve", "P-256")
}

// newFakeACMEServer starts an httptest TLS server implementing just enough of
// RFC 8555 (directory, new-nonce, new-account, new-order, authorization,
// challenge, finalize, certificate download) for golang.org/x/crypto/acme's
// client to complete a full certificate issuance flow against it. It always
// approves the http-01 challenge and returns a self-signed certificate for
// certCN, mirroring the pattern already proven in
// pkg/acme/client/client_test.go (TestRequestCertificate_SuccessWithStorageAndCleanup).
func newFakeACMEServer(t *testing.T, certCN string) *httptest.Server {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fake CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: certCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create fake leaf certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+strconv.FormatInt(time.Now().UnixNano(), 10))

		switch r.URL.Path {
		case "/directory":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":   server.URL + "/new-nonce",
				"newAccount": server.URL + "/new-account",
				"newOrder":   server.URL + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid"})
		case "/new-order":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":         "pending",
				"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"finalize":       server.URL + "/order/1/finalize",
				"authorizations": []string{server.URL + "/authz/1"},
			})
		case "/authz/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": certCN},
				"challenges": []map[string]interface{}{
					{"type": "http-01", "url": server.URL + "/challenge/1", "token": "test-token", "status": "valid"},
				},
			})
		case "/challenge/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "http-01", "url": server.URL + "/challenge/1", "token": "test-token", "status": "valid",
			})
		case "/order/1/finalize":
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid", "certificate": server.URL + "/cert/1"})
		case "/order/1":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "valid", "certificate": server.URL + "/cert/1"})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

// fakeServerTrustPEM PEM-encodes the leaf certificate presented by an
// httptest.Server so it can be supplied as an AccountConfig.TrustedRoots
// entry, letting the real (non-SystemCertPool) HTTP client trust it.
func fakeServerTrustPEM(server *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
}

// =============================================================================
// accountAddCmd
// =============================================================================

func TestAccountAddCmd_Success(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("storage.options.path", t.TempDir())

	resetAccountAddFlags(t)
	f := accountAddCmd.Flags()
	_ = f.Set("directory", "https://ca.example.com/directory")
	_ = f.Set("email", "add@example.com")

	cmd := accountAddCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := accountAddCmd.RunE(cmd, []string{"newacct"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "added successfully") {
		t.Errorf("expected success message, got: %q", buf.String())
	}
}

func TestAccountAddCmd_ValidationFailure(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	// Directory and email are left empty, which fails validateAccountConfig.
	resetAccountAddFlags(t)

	cmd := accountAddCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := accountAddCmd.RunE(cmd, []string{"badacct"})
	if err == nil {
		t.Fatal("expected validation error for missing directory/email")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected directory validation error, got: %v", err)
	}
}

func TestAccountAddCmd_ClientCreationFailure(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("storage.options.path", t.TempDir())

	resetAccountAddFlags(t)
	f := accountAddCmd.Flags()
	_ = f.Set("directory", "https://ca.example.com/directory")
	_ = f.Set("email", "bad-algo@example.com")
	_ = f.Set("key-algorithm", "BOGUS")

	cmd := accountAddCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := accountAddCmd.RunE(cmd, []string{"bogusacct"})
	if err == nil {
		t.Fatal("expected client creation error for unsupported key algorithm")
	}
}

// =============================================================================
// accountListCmd (non-empty)
// =============================================================================

func TestAccountListCmd_NonEmpty(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("accounts", map[string]interface{}{
		"a-short": map[string]interface{}{
			"directory": "https://a.example.com/directory",
			"email":     "a@example.com",
			"key":       map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
		},
		"a-very-long-account-name-for-width": map[string]interface{}{
			"directory": "https://really-long-directory-host.example.com/acme/directory/path",
			"email":     "long@example.com",
			"key":       map[string]interface{}{"algorithm": "RSA", "store": "software"},
		},
	})

	cmd := accountListCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := accountListCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "a-very-long-account-name-for-width") {
		t.Errorf("expected long account name in output: %q", out)
	}
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "DIRECTORY") || !strings.Contains(out, "EMAIL") {
		t.Errorf("expected header columns in output: %q", out)
	}
}

// =============================================================================
// accountShowCmd
// =============================================================================

func TestAccountShowCmd_Success_AllFields(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("accounts", map[string]interface{}{
		"full": map[string]interface{}{
			"directory":   "https://ca.example.com/directory",
			"email":       "full@example.com",
			"key":         map[string]interface{}{"algorithm": "ECDSA", "store": "software", "ecc": map[string]interface{}{"curve": "P-384"}},
			"transport":   "grpc",
			"server_addr": "127.0.0.1:9443",
		},
	})

	cmd := accountShowCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := accountShowCmd.RunE(cmd, []string{"full"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"full@example.com", "ECDSA", "software", "grpc", "127.0.0.1:9443"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output: %q", want, out)
		}
	}
}

func TestAccountShowCmd_NotFound(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := accountShowCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := accountShowCmd.RunE(cmd, []string{"missing"})
	if err == nil {
		t.Fatal("expected error for missing account")
	}
}

// =============================================================================
// accountRemoveCmd
// =============================================================================

func TestAccountRemoveCmd_Success(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("accounts", map[string]interface{}{
		"removable": map[string]interface{}{
			"directory": "https://ca.example.com/directory",
			"email":     "rm@example.com",
			"key":       map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
		},
	})

	cmd := accountRemoveCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := accountRemoveCmd.RunE(cmd, []string{"removable"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "removed successfully") {
		t.Errorf("expected removal confirmation, got: %q", buf.String())
	}
}

func TestAccountRemoveCmd_NotFound(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := accountRemoveCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := accountRemoveCmd.RunE(cmd, []string{"missing"})
	if err == nil {
		t.Fatal("expected error for missing account")
	}
}

// =============================================================================
// certRequestCmd
// =============================================================================

func TestCertRequestCmd_UnknownSpec(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := certRequestCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := certRequestCmd.RunE(cmd, []string{"nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown certificate spec")
	}
}

func TestCertRequestCmd_Success(t *testing.T) {
	server := newFakeACMEServer(t, "example.com")
	defer server.Close()

	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("storage.options.path", t.TempDir())
	viper.Set("accounts", map[string]interface{}{
		"trusted-ca": map[string]interface{}{
			"directory":     server.URL + "/directory",
			"email":         "test@example.com",
			"key":           map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
			"trusted_roots": []string{fakeServerTrustPEM(server)},
		},
	})
	viper.Set("certificates", map[string]interface{}{
		"web": map[string]interface{}{
			"account":   "trusted-ca",
			"subject":   map[string]interface{}{"cn": "example.com"},
			"key":       map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
			"challenge": "http-01",
		},
	})

	cmd := certRequestCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := certRequestCmd.RunE(cmd, []string{"web"}); err != nil {
		t.Fatalf("expected successful certificate issuance, got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "issued successfully") {
		t.Errorf("expected issued successfully in output: %q", out)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("expected subject in output: %q", out)
	}
}

// =============================================================================
// certListCmd (non-empty)
// =============================================================================

func TestCertListCmd_NonEmpty(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	_ = certListCmd.Flags().Set("account", "")
	viper.Set("certificates", map[string]interface{}{
		"short": map[string]interface{}{
			"account": "acct1",
			"subject": map[string]interface{}{"cn": "s.example.com"},
			"key":     map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
		},
		"a-very-long-cert-spec-name-for-width": map[string]interface{}{
			"account":   "a-very-long-account-name",
			"subject":   map[string]interface{}{"cn": "very-long-subject-name.example.com"},
			"key":       map[string]interface{}{"algorithm": "RSA", "store": "software"},
			"challenge": "dns-01",
		},
	})

	cmd := certListCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := certListCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "http-01") {
		t.Errorf("expected default challenge http-01 in output: %q", out)
	}
	if !strings.Contains(out, "dns-01") {
		t.Errorf("expected dns-01 challenge in output: %q", out)
	}
	if !strings.Contains(out, "a-very-long-cert-spec-name-for-width") {
		t.Errorf("expected long spec name in output: %q", out)
	}
}

// =============================================================================
// certShowCmd
// =============================================================================

func TestCertShowCmd_NotFoundAnywhere(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := certShowCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := certShowCmd.RunE(cmd, []string{"nope"})
	if err == nil {
		t.Fatal("expected error for unknown certificate")
	}
}

func TestCertShowCmd_UnissuedSpec(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("certificates", map[string]interface{}{
		"pending-cert": map[string]interface{}{
			"account": "acct1",
			"subject": map[string]interface{}{"cn": "pending.example.com"},
			"key":     map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
		},
	})

	cmd := certShowCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := certShowCmd.RunE(cmd, []string{"pending-cert"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "not yet issued") {
		t.Errorf("expected not-yet-issued message in output: %q", out)
	}
	if !strings.Contains(out, "pending.example.com") {
		t.Errorf("expected subject in output: %q", out)
	}
}

// =============================================================================
// certRenewCmd
// =============================================================================

func TestCertRenewCmd_UnknownSpec(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := certRenewCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := certRenewCmd.RunE(cmd, []string{"nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown certificate spec")
	}
}

func TestCertRenewCmd_Success(t *testing.T) {
	server := newFakeACMEServer(t, "renew.example.com")
	defer server.Close()

	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("storage.options.path", t.TempDir())
	viper.Set("accounts", map[string]interface{}{
		"trusted-ca": map[string]interface{}{
			"directory":     server.URL + "/directory",
			"email":         "renew@example.com",
			"key":           map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
			"trusted_roots": []string{fakeServerTrustPEM(server)},
		},
	})
	viper.Set("certificates", map[string]interface{}{
		"renewable": map[string]interface{}{
			"account":   "trusted-ca",
			"subject":   map[string]interface{}{"cn": "renew.example.com"},
			"key":       map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
			"challenge": "http-01",
		},
	})

	cmd := certRenewCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := certRenewCmd.RunE(cmd, []string{"renewable"}); err != nil {
		t.Fatalf("expected successful renewal, got: %v", err)
	}
	if !strings.Contains(buf.String(), "renewed successfully") {
		t.Errorf("expected renewed successfully in output: %q", buf.String())
	}
}

// =============================================================================
// certRevokeCmd / certDeployCmd (error paths only — see report for why the
// success paths are structurally unreachable from the cmd layer)
// =============================================================================

func TestCertRevokeCmd_UnknownSpec(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	_ = certRevokeCmd.Flags().Set("reason", "0")

	cmd := certRevokeCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := certRevokeCmd.RunE(cmd, []string{"nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown certificate")
	}
}

func TestCertDeployCmd_UnknownSpec(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := certDeployCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := certDeployCmd.RunE(cmd, []string{"nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown certificate")
	}
}

// =============================================================================
// serviceStatusCmd (with configured certificates)
// =============================================================================

func TestServiceStatusCmd_WithCerts(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("certificates", map[string]interface{}{
		"auto1": map[string]interface{}{
			"account": "acct1",
			"subject": map[string]interface{}{"cn": "auto1.example.com"},
			"key":     map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
			"renewal": map[string]interface{}{"auto": true, "days_before": 20},
		},
		"manual1": map[string]interface{}{
			"account": "acct1",
			"subject": map[string]interface{}{"cn": "manual1.example.com"},
			"key":     map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
		},
	})

	cmd := serviceStatusCmd
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := serviceStatusCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "2 total") {
		t.Errorf("expected 2 total certs in output: %q", out)
	}
	if !strings.Contains(out, "1 auto-renew") {
		t.Errorf("expected 1 auto-renew in output: %q", out)
	}
}

// =============================================================================
// serviceStartCmd — signal-triggered graceful shutdown
// =============================================================================

// TestServiceStartCmd_SignalShutdown drives serviceStartCmd.RunE through its
// full lifecycle: it starts the renewal daemon, blocks on the signal channel,
// then verifies that delivering SIGTERM to the test process unblocks it and
// triggers a graceful StopRenewal(). The RunE call runs in a goroutine with a
// bounded wait so a delivery failure cannot hang the test suite.
func TestServiceStartCmd_SignalShutdown(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")

	cmd := serviceStartCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	done := make(chan error, 1)
	go func() {
		done <- serviceStartCmd.RunE(cmd, nil)
	}()

	// Give the goroutine time to reach signal.Notify before delivering SIGTERM.
	time.Sleep(150 * time.Millisecond)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error from serviceStartCmd.RunE: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serviceStartCmd.RunE did not return after SIGTERM was delivered")
	}

	out := buf.String()
	if !strings.Contains(out, "Renewal service started") {
		t.Errorf("expected start message in output: %q", out)
	}
	if !strings.Contains(out, "shutting down") {
		t.Errorf("expected shutdown message in output: %q", out)
	}
	if !strings.Contains(out, "Renewal service stopped") {
		t.Errorf("expected stop message in output: %q", out)
	}
}

// =============================================================================
// rootCmd — Run / PersistentPreRunE closures
// =============================================================================

func TestRootCmd_Run_NoDisplayFallback(t *testing.T) {
	// The "no subcommand specified" line is written via fmt.Println directly
	// to os.Stdout (not cmd.Out), so we only assert on the cmd.Help() output
	// that the fallback branch triggers via cmd.SetOut.
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	rootCmd.Run(rootCmd, nil)

	out := buf.String()
	if !strings.Contains(out, "Usage:") || !strings.Contains(out, "Available Commands") {
		t.Errorf("expected cmd.Help() output, got: %q", out)
	}
}

func TestRootCmd_PersistentPreRunE_CallsInitConfig(t *testing.T) {
	viper.Reset()
	viper.Set("logging.level", "info")

	cmd := &cobra.Command{}
	if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error from PersistentPreRunE: %v", err)
	}
}

// =============================================================================
// versionCmd — PersistentPreRunE closure
// =============================================================================

func TestVersionCmd_PersistentPreRunE(t *testing.T) {
	if err := versionCmd.PersistentPreRunE(&cobra.Command{}, nil); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// =============================================================================
// expandPath — os.UserHomeDir() failure branch
// =============================================================================

func TestExpandPath_HomeDirUnset(t *testing.T) {
	origHome, hadHome := os.LookupEnv("HOME")
	os.Unsetenv("HOME")
	t.Cleanup(func() {
		if hadHome {
			os.Setenv("HOME", origHome)
		}
	})

	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir() still resolves without $HOME on this platform")
	}

	got := expandPath("~/foo")
	if got != "~/foo" {
		t.Errorf("expected unchanged path when home dir lookup fails, got %q", got)
	}
}

// =============================================================================
// loadConfigFile — default search hit
// =============================================================================

func TestLoadConfigFile_DefaultSearchFindsExistingFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "found.yaml")
	if err := os.WriteFile(cfg, []byte("logging:\n  level: debug\n"), 0600); err != nil {
		t.Fatal(err)
	}

	orig := configSearchPaths
	t.Cleanup(func() { configSearchPaths = orig })
	configSearchPaths = []string{cfg}

	viper.Reset()
	if err := loadConfigFile(""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// initConfig — propagated errors
// =============================================================================

func TestInitConfig_LoadConfigFileError(t *testing.T) {
	dir := t.TempDir()
	badCfg := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badCfg, []byte(":\ninvalid\nyaml\n::\n"), 0600); err != nil {
		t.Fatal(err)
	}

	orig := configSearchPaths
	t.Cleanup(func() { configSearchPaths = orig })
	configSearchPaths = []string{"/nonexistent-xyz-path-for-test.yaml"}

	viper.Reset()
	viper.Set("config", badCfg)

	err := initConfig()
	if err == nil {
		t.Fatal("expected error from invalid config file")
	}
	var e ErrConfigRead
	if !errors.As(err, &e) {
		t.Errorf("expected ErrConfigRead, got %T: %v", err, err)
	}
}

func TestInitConfig_ValidationFailure(t *testing.T) {
	orig := configSearchPaths
	t.Cleanup(func() { configSearchPaths = orig })
	configSearchPaths = []string{"/nonexistent-xyz-path-for-test.yaml"}

	viper.Reset()
	viper.Set("logging.level", "not-a-real-level")

	err := initConfig()
	if err == nil {
		t.Fatal("expected validation error for invalid log level")
	}
	var e ErrInvalidLogLevel
	if !errors.As(err, &e) {
		t.Errorf("expected ErrInvalidLogLevel, got %T: %v", err, err)
	}
}

// =============================================================================
// buildServiceConfig — Unmarshal error / nil map recovery
// =============================================================================

func TestBuildServiceConfig_UnmarshalError_ReturnsUsableDefault(t *testing.T) {
	viper.Reset()
	setDefaults()
	// "accounts" must decode into map[string]*AccountConfig; a scalar string
	// cannot be decoded into that type and forces viper.Unmarshal to fail.
	viper.Set("accounts", "not-a-map")

	cfg := buildServiceConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config even when Unmarshal fails")
	}
}

func TestBuildServiceConfig_NilAccountsAndCertificates(t *testing.T) {
	viper.Reset()
	setDefaults()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nil-maps.yaml")
	if err := os.WriteFile(cfgPath, []byte("accounts: ~\ncertificates: ~\n"), 0600); err != nil {
		t.Fatal(err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	cfg := buildServiceConfig()
	if cfg.Accounts == nil {
		t.Error("expected Accounts map to be initialized when config value is null")
	}
	if cfg.Certificates == nil {
		t.Error("expected Certificates map to be initialized when config value is null")
	}
}
