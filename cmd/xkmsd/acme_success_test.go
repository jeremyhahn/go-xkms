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
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	acmeentities "github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
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
	// Trust exactly the listener's own self-signed certificate, and verify
	// it against the name it was issued for.
	certPEM, err := os.ReadFile(cfg.ACME.TLS.CertFile)
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

	// The health endpoint reports the shared datastore through the go-qrdb
	// SDK health checker startACMEServer wires in.
	healthResp, err := client.Get("https://" + addr + "/acme/health")
	if err != nil {
		t.Fatalf("GET /acme/health: %v", err)
	}
	defer func() { _ = healthResp.Body.Close() }()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /acme/health = %d, want 200", healthResp.StatusCode)
	}
	var status handlers.HealthStatus
	if err := json.NewDecoder(healthResp.Body).Decode(&status); err != nil {
		t.Fatalf("decode /acme/health: %v", err)
	}
	if len(status.Checks) != 1 || status.Checks[0].Name != datastore.HealthCheckName ||
		status.Checks[0].Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Fatalf("/acme/health checks = %+v, want one healthy %q check", status.Checks, datastore.HealthCheckName)
	}
}

// TestStartACMEServer_StoresInTheServerDatastore proves the ACME server keeps
// its accounts, orders and certificates in the server's datastore: what it
// saves through its storage factory, a second factory built independently
// from the datastore's DAO factory reads back.
func TestStartACMEServer_StoresInTheServerDatastore(t *testing.T) {
	srv, _ := newEmbeddedQRDBServerWithCA(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ACME: acmeSuccessConfig(t)}

	as, err := startACMEServer(srv, cfg, logger)
	if err != nil {
		t.Fatalf("startACMEServer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := as.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	ctx := t.Context()
	written := as.StorageFactory()
	accounts, err := written.AccountDAO()
	if err != nil {
		t.Fatalf("AccountDAO: %v", err)
	}
	account := &acmeentities.ACMEAccount{Contact: []string{"mailto:ops@example.com"}, CreatedAt: time.Now().UTC()}
	if err := accounts.Save(ctx, account); err != nil {
		t.Fatalf("save account: %v", err)
	}
	orders, err := written.OrderDAO(account.ID)
	if err != nil {
		t.Fatalf("OrderDAO: %v", err)
	}
	order := &acmeentities.ACMEOrder{Status: "pending", AccountID: account.ID,
		Identifiers: []acmeentities.ACMEIdentifier{{Type: "dns", Value: "kms.example.com"}}}
	if err := orders.Save(ctx, order); err != nil {
		t.Fatalf("save order: %v", err)
	}
	certs, err := written.CertificateDAO()
	if err != nil {
		t.Fatalf("CertificateDAO: %v", err)
	}
	cert := &acmeentities.ACMECertificate{Serial: "1a2b3c", PEM: "pem", Status: "valid", IssuedAt: time.Now().UTC()}
	if err := acmestorage.SaveCertificateNoCollision(ctx, certs, cert); err != nil {
		t.Fatalf("save certificate: %v", err)
	}

	read, err := acmeobjstore.NewFactory(srv.Datastore().DAOFactory())
	if err != nil {
		t.Fatalf("NewFactory over the server datastore: %v", err)
	}
	readAccounts, err := read.AccountDAO()
	if err != nil {
		t.Fatalf("AccountDAO: %v", err)
	}
	gotAccount, err := readAccounts.Get(ctx, account.ID)
	if err != nil || len(gotAccount.Contact) != 1 || gotAccount.Contact[0] != "mailto:ops@example.com" {
		t.Fatalf("read account = %+v, %v; want the saved account", gotAccount, err)
	}
	readOrders, err := read.OrderDAO(account.ID)
	if err != nil {
		t.Fatalf("OrderDAO: %v", err)
	}
	gotOrder, err := readOrders.Get(ctx, order.ID)
	if err != nil || gotOrder.AccountID != account.ID || gotOrder.Identifiers[0].Value != "kms.example.com" {
		t.Fatalf("read order = %+v, %v; want the saved order", gotOrder, err)
	}
	readCerts, err := read.CertificateDAO()
	if err != nil {
		t.Fatalf("CertificateDAO: %v", err)
	}
	gotCert, err := readCerts.Get(ctx, cert.EntityID())
	if err != nil || gotCert.Serial != "1a2b3c" {
		t.Fatalf("read certificate = %+v, %v; want the saved certificate", gotCert, err)
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
