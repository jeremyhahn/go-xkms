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
	"errors"
	"fmt"
	"io"
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

	// accountKeys tracks the JWK (RFC 7517, encoded as jwkEncode in
	// golang.org/x/crypto/acme produces it — deterministic per public key)
	// of every account key that has completed a newAccount request, so a
	// repeat request for the same key is answered per RFC 8555 §7.3.1
	// rather than treated as a brand new account.
	accountKeys map[string]bool
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
	mux.HandleFunc("/revoke-cert", d.handleRevokeCert)

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

// handleNewAccount implements RFC 8555 §7.3's newAccount semantics for the
// two request shapes golang.org/x/crypto/acme sends, distinguished by the
// account key's JWK (every newAccount request is JWK-signed — there is no
// KID yet):
//
//   - A registration request (Client.Register): the first request for a
//     given key gets 201 Created with a fresh account; a repeat request for
//     a key that already completed one gets 200 OK with the existing
//     account, per §7.3.1. The client library turns a 200 here into
//     ErrAccountAlreadyExists after caching the returned account URL as its
//     KID — the idempotent path production code (and go-xkms#988's tests)
//     depends on.
//   - A POST-as-GET existing-account lookup (Client.GetReg, payload
//     {"onlyReturnExisting":true}): 200 OK with the existing account if the
//     key is known, otherwise 404 with an accountDoesNotExist problem
//     document, per §7.3.1.
func (d *FakeACMEDirectory) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	jwk, onlyReturnExisting, err := parseACMEAccountJWS(r)
	if err != nil {
		d.setHeaders(w)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:malformed",
			"detail": err.Error(),
		})
		return
	}

	d.mu.Lock()
	known := d.accountKeys[jwk]
	if onlyReturnExisting && !known {
		d.mu.Unlock()
		d.setHeaders(w)
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "urn:ietf:params:acme:error:accountDoesNotExist",
			"detail": "no account associated with this key",
		})
		return
	}
	if !known {
		if d.accountKeys == nil {
			d.accountKeys = make(map[string]bool)
		}
		d.accountKeys[jwk] = true
	}
	d.mu.Unlock()

	d.setHeaders(w)
	w.Header().Set("Location", d.URL+"/account/1")
	if known {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "valid",
		"contact": []string{"mailto:test@example.com"},
		"orders":  d.URL + "/account/1/orders",
	})
}

// parseACMEAccountJWS extracts the account public key (as its raw JWK JSON,
// a stable identity for a given key since golang.org/x/crypto/acme encodes
// it deterministically with a fixed field order) and the
// "onlyReturnExisting" flag from a JWS-wrapped newAccount request body, per
// RFC 7515 §3.2 and RFC 8555 §7.3.
func parseACMEAccountJWS(r *http.Request) (jwk string, onlyReturnExisting bool, err error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", false, err
	}

	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		return "", false, err
	}

	protectedJSON, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return "", false, err
	}
	var protected struct {
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		return "", false, err
	}
	if len(protected.JWK) == 0 {
		return "", false, errors.New("newAccount request missing jwk in protected header")
	}

	if jws.Payload != "" {
		payloadJSON, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			return "", false, err
		}
		var payload struct {
			OnlyReturnExisting bool `json:"onlyReturnExisting"`
		}
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			return "", false, err
		}
		onlyReturnExisting = payload.OnlyReturnExisting
	}

	return string(protected.JWK), onlyReturnExisting, nil
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

// handleRevokeCert accepts any well-formed revocation request and reports
// success, mirroring the rest of this fake: it proves out client code that
// drives golang.org/x/crypto/acme.Client.RevokeCert, not CA revocation
// business logic (belongs to pkg/acme/server's own tests).
func (d *FakeACMEDirectory) handleRevokeCert(w http.ResponseWriter, _ *http.Request) {
	d.setHeaders(w)
	w.WriteHeader(http.StatusOK)
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
