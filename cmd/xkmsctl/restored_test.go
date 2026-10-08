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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckServerResponse_201Created(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"new-resource"}`))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	body, err := checkServerResponse(resp)
	if err != nil {
		t.Fatalf("checkServerResponse should succeed for 201: %v", err)
	}
	if string(body) != `{"id":"new-resource"}` {
		t.Fatalf("unexpected body: %s", string(body))
	}
}
func TestCheckServerResponse_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"already claimed"}`))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	_, err = checkServerResponse(resp)
	if err == nil {
		t.Fatal("expected error for 409 status")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}
func TestCheckServerResponse_ServerErrorNoJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	_, err = checkServerResponse(resp)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}
func TestCheckServerResponse_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	body, err := checkServerResponse(resp)
	if err != nil {
		t.Fatalf("checkServerResponse failed: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("unexpected body: %s", string(body))
	}
}
func TestCreateServerHTTPClient_MTLSMissingCert(t *testing.T) {
	oldFactory := serverHTTPClientFactory
	defer func() { serverHTTPClientFactory = oldFactory }()
	serverHTTPClientFactory = nil

	cfg := &Config{TLSCert: "", TLSKey: ""}
	_, err := createServerHTTPClient(cfg, false)
	if err == nil {
		t.Fatal("expected error for missing mTLS cert/key")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}
func TestCreateServerHTTPClient_SPKIRequired(t *testing.T) {
	oldFactory := serverHTTPClientFactory
	defer func() { serverHTTPClientFactory = oldFactory }()
	serverHTTPClientFactory = nil

	cfg := &Config{SPKIPin: ""}
	_, err := createServerHTTPClient(cfg, true)
	if !errors.Is(err, ErrSPKIPinRequired) {
		t.Fatalf("expected ErrSPKIPinRequired, got: %v", err)
	}
}
func TestCreateServerHTTPClient_SPKISuccess(t *testing.T) {
	oldFactory := serverHTTPClientFactory
	defer func() { serverHTTPClientFactory = oldFactory }()
	serverHTTPClientFactory = nil

	cfg := &Config{SPKIPin: "abc123deadbeef"}
	client, err := createServerHTTPClient(cfg, true)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}
func TestCreateServerHTTPClient_TestFactory(t *testing.T) {
	oldFactory := serverHTTPClientFactory
	defer func() { serverHTTPClientFactory = oldFactory }()

	expectedClient := &http.Client{}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return expectedClient, nil
	}

	client, err := createServerHTTPClient(&Config{}, false)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client != expectedClient {
		t.Fatal("expected factory-injected client")
	}
}
func TestDoServerRequest_InvalidURL(t *testing.T) {
	_, err := doServerRequest(http.DefaultClient, http.MethodGet, "://invalid-url", nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !errors.Is(err, ErrHTTPRequestFailed) {
		t.Fatalf("expected ErrHTTPRequestFailed, got: %v", err)
	}
}
func TestDoServerRequest_MarshalAndSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type, got %s", r.Header.Get("Content-Type"))
		}

		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if body["username"] != "test@example.com" {
			t.Errorf("expected username test@example.com, got %s", body["username"])
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"nonce":"abc123"}`))
	}))
	defer server.Close()

	resp, err := doServerRequest(server.Client(), http.MethodPost, server.URL,
		map[string]string{"username": "test@example.com"})
	if err != nil {
		t.Fatalf("doServerRequest failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
func TestDoServerRequest_NilBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"enrolling"}`))
	}))
	defer server.Close()

	resp, err := doServerRequest(server.Client(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("doServerRequest with nil body failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
func TestDoServerRequest_UnmarshalableBody(t *testing.T) {
	// Channels cannot be JSON-marshalled
	_, err := doServerRequest(http.DefaultClient, http.MethodPost, "http://localhost", make(chan int))
	if err == nil {
		t.Fatal("expected error for unmarshalable body")
	}
	if !errors.Is(err, ErrJSONMarshalFailed) {
		t.Fatalf("expected ErrJSONMarshalFailed, got: %v", err)
	}
}
func TestNewMTLSHTTPClient_InvalidCAFile(t *testing.T) {
	certFile, keyFile := generateTempCertKeyPair(t)

	_, err := newMTLSHTTPClient(certFile, keyFile, "/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}
func TestNewMTLSHTTPClient_InvalidCAPEM(t *testing.T) {
	certFile, keyFile := generateTempCertKeyPair(t)

	// Write garbage CA file
	caFile := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(caFile, []byte("not a cert"), 0644); err != nil {
		t.Fatalf("failed to write bad CA file: %v", err)
	}

	_, err := newMTLSHTTPClient(certFile, keyFile, caFile)
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
	if !errors.Is(err, ErrInvalidCA) {
		t.Fatalf("expected ErrInvalidCA, got: %v", err)
	}
}
func TestNewMTLSHTTPClient_InvalidCertFile(t *testing.T) {
	_, err := newMTLSHTTPClient("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}
func TestNewMTLSHTTPClient_ValidCertKey(t *testing.T) {
	certFile, keyFile := generateTempCertKeyPair(t)

	client, err := newMTLSHTTPClient(certFile, keyFile, "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatal("expected exactly 1 client certificate")
	}
}
func TestNewMTLSHTTPClient_WithValidCA(t *testing.T) {
	certFile, keyFile := generateTempCertKeyPair(t)

	// Generate a self-signed CA cert to use as CA file
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		IsCA:         true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	client, err := newMTLSHTTPClient(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected non-nil RootCAs")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("expected MinVersion TLS 1.3")
	}
}
func TestNewSPKIHTTPClient_DifferentPins(t *testing.T) {
	client1 := newSPKIHTTPClient("pin1")
	client2 := newSPKIHTTPClient("pin2")
	if client1 == client2 {
		t.Fatal("expected distinct clients for different pins")
	}
}
func TestNewSPKIHTTPClient_HasVerifyConnection(t *testing.T) {
	client := newSPKIHTTPClient("abc123deadbeef")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	// VerifyConnection must be set: this IS the actual peer authentication
	// for trust bootstrap (SPKI pin check replaces CA chain verification).
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("expected VerifyConnection callback to be set for SPKI pin verification")
	}
	// SessionTicketsDisabled must be true so session resumption cannot
	// bypass the VerifyConnection pin check (CWE-295).
	if !transport.TLSClientConfig.SessionTicketsDisabled {
		t.Fatal("expected SessionTicketsDisabled=true to prevent pin bypass via session resumption")
	}
}
func TestOutputJSON_Success(t *testing.T) {
	err := outputJSON(map[string]string{"state": "enrolling"})
	if err != nil {
		t.Fatalf("outputJSON failed: %v", err)
	}
}
func TestOutputJSON_UnmarshalableValue(t *testing.T) {
	// Channels cannot be marshalled
	err := outputJSON(make(chan int))
	if err == nil {
		t.Fatal("expected error for unmarshalable value")
	}
	if !errors.Is(err, ErrJSONMarshalFailed) {
		t.Fatalf("expected ErrJSONMarshalFailed, got: %v", err)
	}
}
func TestRootCmd_SOPinFlag(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("so-pin")
	if f == nil {
		t.Fatal("expected --so-pin persistent flag on rootCmd")
	}
}
func TestRootCmd_SPKIPinFlag(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("spki-pin")
	if f == nil {
		t.Fatal("expected --spki-pin persistent flag on rootCmd")
	}
}
