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

package testutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FakeACMEDirectory is a minimal, in-process ACME v2 directory server used
// to drive golang.org/x/crypto/acme.Client-based flows (order creation,
// authorization, challenge acceptance, and finalization) end to end without
// implementing any CA business logic: every authorization offers
// ChallengeTypes, accepting any one of them marks the order ready, and
// Finalize returns Certs (DER, leaf-first) verbatim regardless of the CSR
// bytes the client submitted.
//
// It exists to test client code that must talk to something shaped like a
// real ACME server — including go-xkms's enroll-01 and device-attest-01
// device-identity challenges, whose CSR is a packed TCG-CSR-IDEVID rather
// than a standard PKCS#10 request. Testing an actual CA's issuance and
// TCG-CSR-IDEVID verification logic belongs to pkg/acme/server,
// pkg/acme/challenges and pkg/ca's own tests.
type FakeACMEDirectory struct {
	*httptest.Server

	mu             sync.Mutex
	nonceCounter   int64
	challengeTypes []string
	certs          [][]byte

	orderStatus     string
	authzStatus     string
	challengeStatus string
}

// NewFakeACMEDirectory starts a FakeACMEDirectory offering challengeTypes on
// every authorization and returning certs (DER-encoded, leaf-first) from
// its single order's finalize/certificate endpoints. The server is closed
// automatically when t finishes.
func NewFakeACMEDirectory(t *testing.T, challengeTypes []string, certs [][]byte) *FakeACMEDirectory {
	t.Helper()

	d := &FakeACMEDirectory{
		challengeTypes:  challengeTypes,
		certs:           certs,
		orderStatus:     "pending",
		authzStatus:     "pending",
		challengeStatus: "pending",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", d.handleDirectory)
	mux.HandleFunc("/new-nonce", d.handleNewNonce)
	mux.HandleFunc("/new-account", d.handleNewAccount)
	mux.HandleFunc("/new-order", d.handleNewOrder)
	mux.HandleFunc("/order/1", d.handleOrder)
	mux.HandleFunc("/authz/1", d.handleAuthz)
	mux.HandleFunc("/challenge/", d.handleChallenge)
	mux.HandleFunc("/finalize/1", d.handleFinalize)
	mux.HandleFunc("/cert/1", d.handleCert)

	d.Server = httptest.NewServer(mux)
	t.Cleanup(d.Close)
	return d
}

// DirectoryURL returns the URL client.Config.DirectoryURL expects.
func (d *FakeACMEDirectory) DirectoryURL() string {
	return d.URL + "/directory"
}

func (d *FakeACMEDirectory) nextNonce() string {
	n := atomic.AddInt64(&d.nonceCounter, 1)
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("fake-nonce-%d-%d", n, time.Now().UnixNano())))
}

func (d *FakeACMEDirectory) setHeaders(w http.ResponseWriter) {
	w.Header().Set("Replay-Nonce", d.nextNonce())
	w.Header().Set("Content-Type", "application/json")
}

func (d *FakeACMEDirectory) handleDirectory(w http.ResponseWriter, _ *http.Request) {
	d.setHeaders(w)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"newNonce":   d.URL + "/new-nonce",
		"newAccount": d.URL + "/new-account",
		"newOrder":   d.URL + "/new-order",
		"revokeCert": d.URL + "/revoke-cert",
		"keyChange":  d.URL + "/key-change",
		"meta": map[string]interface{}{
			"termsOfService":          "https://example.com/terms",
			"externalAccountRequired": false,
		},
	})
}

func (d *FakeACMEDirectory) handleNewNonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Replay-Nonce", d.nextNonce())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (d *FakeACMEDirectory) handleNewAccount(w http.ResponseWriter, _ *http.Request) {
	d.setHeaders(w)
	w.Header().Set("Location", d.URL+"/account/1")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
		"orders":  d.URL + "/account/1/orders",
	})
}

func (d *FakeACMEDirectory) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	d.setHeaders(w)

	d.mu.Lock()
	d.orderStatus = "pending"
	d.authzStatus = "pending"
	d.challengeStatus = "pending"
	d.mu.Unlock()

	w.Header().Set("Location", d.URL+"/order/1")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "pending",
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "permanent-identifier", "value": "device-under-test"}},
		"authorizations": []string{d.URL + "/authz/1"},
		"finalize":       d.URL + "/finalize/1",
	})
}

func (d *FakeACMEDirectory) handleOrder(w http.ResponseWriter, r *http.Request) {
	d.setHeaders(w)

	d.mu.Lock()
	status := d.orderStatus
	d.mu.Unlock()

	resp := map[string]interface{}{
		"status":         status,
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "permanent-identifier", "value": "device-under-test"}},
		"authorizations": []string{d.URL + "/authz/1"},
		"finalize":       d.URL + "/finalize/1",
	}
	if status == "valid" {
		resp["certificate"] = d.URL + "/cert/1"
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (d *FakeACMEDirectory) handleAuthz(w http.ResponseWriter, r *http.Request) {
	d.setHeaders(w)

	d.mu.Lock()
	status := d.authzStatus
	d.mu.Unlock()

	challenges := make([]map[string]interface{}, 0, len(d.challengeTypes))
	for i, ct := range d.challengeTypes {
		challenges = append(challenges, map[string]interface{}{
			"type":   ct,
			"url":    fmt.Sprintf("%s/challenge/%d", d.URL, i+1),
			"token":  fmt.Sprintf("fake-token-%d", i+1),
			"status": status,
		})
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     status,
		"identifier": map[string]string{"type": "permanent-identifier", "value": "device-under-test"},
		"challenges": challenges,
		"expires":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
}

func (d *FakeACMEDirectory) handleChallenge(w http.ResponseWriter, r *http.Request) {
	d.setHeaders(w)

	idx := strings.TrimPrefix(r.URL.Path, "/challenge/")
	var challengeType string
	d.mu.Lock()
	for i, ct := range d.challengeTypes {
		if fmt.Sprintf("%d", i+1) == idx {
			challengeType = ct
			break
		}
	}
	if r.Method == http.MethodPost {
		d.challengeStatus = "valid"
		d.authzStatus = "valid"
		d.orderStatus = "ready"
	}
	status := d.challengeStatus
	d.mu.Unlock()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   challengeType,
		"url":    d.URL + "/challenge/" + idx,
		"token":  "fake-token-" + idx,
		"status": status,
	})
}

func (d *FakeACMEDirectory) handleFinalize(w http.ResponseWriter, _ *http.Request) {
	d.setHeaders(w)

	d.mu.Lock()
	d.orderStatus = "valid"
	d.mu.Unlock()

	w.Header().Set("Location", d.URL+"/order/1")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "valid",
		"expires":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "permanent-identifier", "value": "device-under-test"}},
		"authorizations": []string{d.URL + "/authz/1"},
		"finalize":       d.URL + "/finalize/1",
		"certificate":    d.URL + "/cert/1",
	})
}

func (d *FakeACMEDirectory) handleCert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	for _, der := range d.certs {
		_ = pemEncodeCertificate(w, der)
	}
}

// pemEncodeCertificate writes a single PEM-encoded CERTIFICATE block for
// der to w, matching the application/pem-certificate-chain media type
// golang.org/x/crypto/acme.Client.CreateOrderCert parses.
func pemEncodeCertificate(w http.ResponseWriter, der []byte) error {
	_, err := fmt.Fprintf(w, "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n", base64Wrap(der))
	return err
}

// base64Wrap base64-encodes der and inserts a newline every 64 characters,
// the line length PEM (RFC 7468) requires.
func base64Wrap(der []byte) string {
	full := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	for i := 0; i < len(full); i += 64 {
		end := i + 64
		if end > len(full) {
			end = len(full)
		}
		b.WriteString(full[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}
