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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// shippedConfigPath is the configuration file the release ships and the
// board runs.
const shippedConfigPath = "../../configs/xkmsd.yaml"

// TestShippedConfig_ACMEEnabledAndServesDirectory loads the shipped
// configs/xkmsd.yaml and asserts it carries an `acme:` section that passes
// validation and, started on its own listener, serves the ACME directory.
// Only the host-specific values (TLS files, listen port, data dir) are
// replaced for the test.
func TestShippedConfig_ACMEEnabledAndServesDirectory(t *testing.T) {
	cfg, err := config.Load(shippedConfigPath)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", shippedConfigPath, err)
	}
	if cfg.ACME == nil {
		t.Fatalf("%s has no acme: section", shippedConfigPath)
	}
	shipped := *cfg.ACME
	if !shipped.Enabled {
		t.Fatal("shipped acme.enabled = false, want true")
	}
	if shipped.HTTPSAddr == "" || shipped.ExternalURL == "" {
		t.Fatalf("shipped acme https_addr=%q external_url=%q, want both set", shipped.HTTPSAddr, shipped.ExternalURL)
	}
	if len(shipped.CAAIdentities) == 0 {
		t.Error("shipped acme.caa_identities is empty")
	}
	if !shipped.Audit.IsEnabled() {
		t.Error("shipped acme.audit is not enabled")
	}
	if !shipped.RateLimit.IsEnabled() {
		t.Error("shipped acme.rate_limit is not enabled")
	}
	if err := shipped.Validate(); err != nil {
		t.Fatalf("shipped acme section does not validate: %v", err)
	}

	acmeCfg := shipped
	certPath, keyPath := writeACMETestCertAndKey(t, t.TempDir())
	acmeCfg.TLS.CertFile, acmeCfg.TLS.KeyFile = certPath, keyPath
	acmeCfg.HTTPSAddr = "127.0.0.1:0"
	acmeCfg.DataDir = t.TempDir()
	acmeCfg.Audit.LogPath = ""

	srv, _ := newEmbeddedQRDBServerWithCA(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	as, err := startACMEServer(srv, &config.Config{ACME: &acmeCfg}, logger)
	if err != nil {
		t.Fatalf("startACMEServer with the shipped acme section: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := as.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read ACME cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("ACME cert PEM did not parse")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "acme.example.com", MinVersion: tls.VersionTLS12},
		},
	}

	dirPath := shipped.DirectoryPath
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
			t.Fatalf("GET %s never became reachable: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	var dir map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	newAccount, _ := dir["newAccount"].(string)
	if !strings.HasPrefix(newAccount, shipped.ExternalURL) {
		t.Errorf("directory newAccount = %q, want it under the shipped external_url %q", newAccount, shipped.ExternalURL)
	}
}
