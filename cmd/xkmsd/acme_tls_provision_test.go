package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestShippedConfig_ACMEListenerCertIssuedOnFirstStart starts the ACME server
// from a copy of the shipped configs/xkmsd.yaml with no ACME TLS files present:
// xkmsd must issue the listener certificate from its own CA, write it with a
// 0600 key, serve the directory over a chain that verifies against the CA
// root, and reuse the same certificate on the next start.
func TestShippedConfig_ACMEListenerCertIssuedOnFirstStart(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(shippedConfigPath)
	if err != nil {
		t.Fatalf("read %s: %v", shippedConfigPath, err)
	}
	copied := filepath.Join(dir, "xkmsd.yaml")
	if err := os.WriteFile(copied, raw, 0o600); err != nil {
		t.Fatalf("copy shipped config: %v", err)
	}
	cfg, err := config.Load(copied)
	if err != nil {
		t.Fatalf("config.Load(copy): %v", err)
	}
	if cfg.ACME == nil || !cfg.ACME.Enabled {
		t.Fatal("shipped config does not enable ACME")
	}
	acmeCfg := *cfg.ACME
	if acmeCfg.TLS.CertFile == "" || acmeCfg.TLS.KeyFile == "" {
		t.Fatalf("shipped acme.tls cert_file=%q key_file=%q, want both set", acmeCfg.TLS.CertFile, acmeCfg.TLS.KeyFile)
	}
	tlsDir := filepath.Join(dir, "tls")
	acmeCfg.TLS.CertFile = filepath.Join(tlsDir, filepath.Base(acmeCfg.TLS.CertFile))
	acmeCfg.TLS.KeyFile = filepath.Join(tlsDir, filepath.Base(acmeCfg.TLS.KeyFile))
	acmeCfg.HTTPSAddr = "127.0.0.1:0"
	acmeCfg.DataDir = t.TempDir()
	acmeCfg.Audit.LogPath = ""

	srv, _ := newEmbeddedQRDBServerWithCA(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	start := func() *acmeServer {
		t.Helper()
		as, err := startACMEServer(srv, &config.Config{ACME: &acmeCfg}, logger)
		if err != nil {
			t.Fatalf("startACMEServer from the shipped config without TLS files: %v", err)
		}
		return as
	}
	stop := func(as *acmeServer) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := as.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}

	// (a) start succeeds.
	as := start()

	// (b) cert and key now exist, the key private to the owner.
	certPEM, err := os.ReadFile(acmeCfg.TLS.CertFile)
	if err != nil {
		t.Fatalf("listener cert not written: %v", err)
	}
	info, err := os.Stat(acmeCfg.TLS.KeyFile)
	if err != nil {
		t.Fatalf("listener key not written: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("listener key mode = %o, want 600", mode)
	}

	// (c) the directory answers 200 over TLS verified against the CA root.
	roots := x509.NewCertPool()
	root, err := srv.CA().TrustedRoot()
	if err != nil {
		t.Fatalf("CA root: %v", err)
	}
	roots.AddCert(root)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
		},
	}
	dirPath := acmeCfg.DirectoryPath
	if dirPath == "" {
		dirPath = "/acme"
	}
	url := "https://" + as.listener.Addr().String() + dirPath + "/directory"
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s over TLS verified by the CA root: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	stop(as)

	// (d) a second start reuses the certificate.
	as = start()
	defer stop(as)
	again, err := os.ReadFile(acmeCfg.TLS.CertFile)
	if err != nil {
		t.Fatalf("re-read listener cert: %v", err)
	}
	if !bytes.Equal(certPEM, again) {
		t.Error("second start re-issued the listener certificate, want the existing one reused")
	}
}
