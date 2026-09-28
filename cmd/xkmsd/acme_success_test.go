// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Success-path coverage for startACMEServer and (*acmeServer).Shutdown.
// acme_start_failures_test.go and acme_accessors_test.go each stopped short
// of standing up a working TCG CA / ACME TLS listener and said so explicitly
// ("out of this batch's scope" / "per #705 batch D"); this file is that next
// batch. It reuses newEmbeddedQRDBServerWithCA (admin_qrdb_test.go) for the
// real primary CA and writeACMETestCertAndKey (acme_test.go) for the ACME
// listener's self-signed material, rather than hand-rolling either, and
// drives one real HTTPS request through the resulting server before
// shutting it down.

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// acmeSuccessConfig returns an ACMEConfig that satisfies both
// config.ACMEConfig.Validate and startACMEServer's construction path: a
// loopback HTTPS listener on an ephemeral port (":0", never a fixed port)
// and a self-signed cert/key pair for it.
func acmeSuccessConfig(t *testing.T) *config.ACMEConfig {
	t.Helper()
	certPath, keyPath := writeACMETestCertAndKey(t, t.TempDir())
	return &config.ACMEConfig{
		Enabled:         true,
		DataDir:         t.TempDir(),
		HTTPSAddr:       "127.0.0.1:0",
		ExternalURL:     "https://acme.example.com",
		KeystoreBackend: "software",
		CAAIdentities:   []string{"acme.example.com"},
		TLS:             config.ACMETLSConfig{CertFile: certPath, KeyFile: keyPath},
		Challenges:      config.ACMEChallengesConfig{HTTP01: true},
	}
}

// TestStartACMEServer_Success proves the full construction path -- state
// store, CAA validator, rate limiters, REST service, router, TLS listener
// bind, and the serving goroutine -- succeeds end-to-end against a real CA
// and answers a real HTTPS request on its bound ephemeral port.
func TestStartACMEServer_Success(t *testing.T) {
	srv, _ := newEmbeddedQRDBServerWithCA(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ACME: acmeSuccessConfig(t)}

	as, err := startACMEServer(srv, cfg, logger)
	if err != nil {
		t.Fatalf("startACMEServer: %v", err)
	}
	if as == nil {
		t.Fatal("startACMEServer returned a nil *acmeServer with no error")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := as.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	if as.CA() == nil {
		t.Error("acmeServer.CA() = nil, want the primary CA")
	}
	if as.StorageFactory() == nil {
		t.Error("acmeServer.StorageFactory() = nil, want the ACME state storage factory")
	}

	addr := as.listener.Addr().String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test client against our own throwaway cert
		},
	}

	url := "https://" + addr + "/acme/directory"
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
}

// TestStartACMEServer_Success_ClusterEnrollmentEnabled proves that
// startACMEServer succeeds end-to-end when cluster ACME enrollment is also
// enabled (buildClusterPreSignHooks returns a non-nil registry that
// handlers.NewRestService must accept), rather than only exercising the
// registry-construction unit (TestBuildClusterPreSignHooks_Enabled,
// acme_test.go) in isolation of the rest of start-up.
func TestStartACMEServer_Success_ClusterEnrollmentEnabled(t *testing.T) {
	srv, _ := newEmbeddedQRDBServerWithCA(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		ACME: acmeSuccessConfig(t),
		Cluster: config.ClusterConfig{
			Enabled: true,
			RaftEnrollment: config.RaftEnrollmentConfig{
				TrustDomain: "cluster.example.org",
				ACME:        config.RaftACMEEnrollmentConfig{Enabled: true},
			},
		},
	}

	as, err := startACMEServer(srv, cfg, logger)
	if err != nil {
		t.Fatalf("startACMEServer: %v", err)
	}
	if as == nil {
		t.Fatal("startACMEServer returned a nil *acmeServer with no error")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := as.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
}
