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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// signNonce tests
// ---------------------------------------------------------------------------

func TestSignNonce_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	nonce := []byte("test-nonce-data-12345")
	sig, err := signNonce(nonce, key)
	if err != nil {
		t.Fatalf("signNonce failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	// Verify the signature
	hash := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], sig) {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestSignNonce_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	nonce := []byte("test-nonce-data-12345")
	sig, err := signNonce(nonce, key)
	if err != nil {
		t.Fatalf("signNonce failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	// Verify the signature
	hash := sha256.Sum256(nonce)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("RSA signature verification failed: %v", err)
	}
}

func TestSignNonce_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	nonce := []byte("test-nonce-data-12345")
	sig, err := signNonce(nonce, priv)
	if err != nil {
		t.Fatalf("signNonce failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}

	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, nonce, sig) {
		t.Fatal("Ed25519 signature verification failed")
	}
}

func TestSignNonce_UnsupportedKeyType(t *testing.T) {
	// unsupportedKey is not *ecdsa.PrivateKey, *rsa.PrivateKey, or ed25519.PrivateKey
	_, err := signNonce([]byte("nonce"), &unsupportedKey{})
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got: %v", err)
	}
}

// unsupportedKey is a type that does not match any recognized key type in signNonce.
type unsupportedKey struct{}

func TestSignNonce_NilKey(t *testing.T) {
	_, err := signNonce([]byte("nonce"), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// newSPKIHTTPClient tests
// ---------------------------------------------------------------------------

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

func TestNewSPKIHTTPClient_DifferentPins(t *testing.T) {
	client1 := newSPKIHTTPClient("pin1")
	client2 := newSPKIHTTPClient("pin2")
	if client1 == client2 {
		t.Fatal("expected distinct clients for different pins")
	}
}

// ---------------------------------------------------------------------------
// newMTLSHTTPClient tests
// ---------------------------------------------------------------------------

func TestNewMTLSHTTPClient_InvalidCertFile(t *testing.T) {
	_, err := newMTLSHTTPClient("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	if err == nil {
		t.Fatal("expected error for invalid cert files")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
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

// ---------------------------------------------------------------------------
// doInitRequest tests
// ---------------------------------------------------------------------------

func TestDoInitRequest_MarshalAndSend(t *testing.T) {
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

	resp, err := doInitRequest(server.Client(), http.MethodPost, server.URL,
		claimCertBeginRequest{Username: "test@example.com"})
	if err != nil {
		t.Fatalf("doInitRequest failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestDoInitRequest_NilBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"enrolling"}`))
	}))
	defer server.Close()

	resp, err := doInitRequest(server.Client(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("doInitRequest with nil body failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestDoInitRequest_InvalidURL(t *testing.T) {
	_, err := doInitRequest(http.DefaultClient, http.MethodGet, "://invalid-url", nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !errors.Is(err, ErrHTTPRequestFailed) {
		t.Fatalf("expected ErrHTTPRequestFailed, got: %v", err)
	}
}

func TestDoInitRequest_UnmarshalableBody(t *testing.T) {
	// Channels cannot be JSON-marshalled
	_, err := doInitRequest(http.DefaultClient, http.MethodPost, "http://localhost", make(chan int))
	if err == nil {
		t.Fatal("expected error for unmarshalable body")
	}
	if !errors.Is(err, ErrJSONMarshalFailed) {
		t.Fatalf("expected ErrJSONMarshalFailed, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// checkServerResponse tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// outputJSON tests
// ---------------------------------------------------------------------------

func TestOutputJSON_Success(t *testing.T) {
	err := outputJSON(initStatusResponse{State: "enrolling"})
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

// ---------------------------------------------------------------------------
// createInitHTTPClient tests
// ---------------------------------------------------------------------------

func TestCreateInitHTTPClient_SPKIRequired(t *testing.T) {
	oldFactory := initHTTPClientFactory
	defer func() { initHTTPClientFactory = oldFactory }()
	initHTTPClientFactory = nil

	cfg := &Config{SPKIPin: ""}
	_, err := createInitHTTPClient(cfg, true)
	if !errors.Is(err, ErrSPKIPinRequired) {
		t.Fatalf("expected ErrSPKIPinRequired, got: %v", err)
	}
}

func TestCreateInitHTTPClient_SPKISuccess(t *testing.T) {
	oldFactory := initHTTPClientFactory
	defer func() { initHTTPClientFactory = oldFactory }()
	initHTTPClientFactory = nil

	cfg := &Config{SPKIPin: "abc123deadbeef"}
	client, err := createInitHTTPClient(cfg, true)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestCreateInitHTTPClient_MTLSMissingCert(t *testing.T) {
	oldFactory := initHTTPClientFactory
	defer func() { initHTTPClientFactory = oldFactory }()
	initHTTPClientFactory = nil

	cfg := &Config{TLSCert: "", TLSKey: ""}
	_, err := createInitHTTPClient(cfg, false)
	if err == nil {
		t.Fatal("expected error for missing mTLS cert/key")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}

func TestCreateInitHTTPClient_TestFactory(t *testing.T) {
	oldFactory := initHTTPClientFactory
	defer func() { initHTTPClientFactory = oldFactory }()

	expectedClient := &http.Client{}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return expectedClient, nil
	}

	client, err := createInitHTTPClient(&Config{}, false)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if client != expectedClient {
		t.Fatal("expected factory-injected client")
	}
}

// ---------------------------------------------------------------------------
// initCmd subcommand registration tests
// ---------------------------------------------------------------------------

func TestInitCmd_SubcommandRegistration(t *testing.T) {
	subcommands := initCmd.Commands()
	expected := map[string]bool{
		"status":      false,
		"claim-cert":  false,
		"claim-share": false,
		"sign-csr":    false,
	}

	for _, cmd := range subcommands {
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected subcommand %q not found on initCmd", name)
		}
	}
}

func TestClaimCertCmd_Flags(t *testing.T) {
	flags := []string{"username", "key", "spki-pin", "output", "ca-output"}
	for _, name := range flags {
		f := claimCertCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag --%s on claim-cert command", name)
		}
	}
}

func TestClaimShareCmd_Flags(t *testing.T) {
	flags := []string{"username", "cert", "key", "ca-cert", "spki-pin", "output"}
	for _, name := range flags {
		f := claimShareCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag --%s on claim-share command", name)
		}
	}
}

func TestInitSignCSRCmd_Flags(t *testing.T) {
	flags := []string{"username", "csr", "role", "output"}
	for _, name := range flags {
		f := initSignCSRCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag --%s on sign-csr command", name)
		}
	}
}

// ---------------------------------------------------------------------------
// runInitStatus tests
// ---------------------------------------------------------------------------

func TestRunInitStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/init/status" {
			t.Errorf("expected path /api/v1/init/status, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"enrolling"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runInitStatus(initStatusCmd, nil)
	if err != nil {
		t.Fatalf("runInitStatus failed: %v", err)
	}
}

func TestRunInitStatus_JSONOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"state":"sealed"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "json",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runInitStatus(initStatusCmd, nil)
	if err != nil {
		t.Fatalf("runInitStatus with JSON output failed: %v", err)
	}
}

func TestRunInitStatus_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server down"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runInitStatus(initStatusCmd, nil)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

func TestRunInitStatus_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	err := runInitStatus(initStatusCmd, nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
	if !errors.Is(err, ErrJSONParseFailed) {
		t.Fatalf("expected ErrJSONParseFailed, got: %v", err)
	}
}

func TestRunInitStatus_ClientCreateError(t *testing.T) {
	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	// No factory set, no TLS cert/key set => mTLS path fails
	initHTTPClientFactory = nil
	globalConfig = &Config{
		Server:  "https://localhost:8443",
		TLSCert: "",
		TLSKey:  "",
	}

	err := runInitStatus(initStatusCmd, nil)
	if err == nil {
		t.Fatal("expected error when HTTP client creation fails")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runClaimCert tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// runClaimCert tests
//
// The claim-cert protocol is a proof of possession: the officer signs the
// server's nonce with the private key whose public half was submitted in the
// CSR. Every success-path test below therefore verifies the signature server
// side with a real key, which is what makes these tests catch the class of bug
// where the client signs with the wrong key.
// ---------------------------------------------------------------------------

// writeTestKeyPEM writes key to a PKCS#8 PEM file in a temp dir and returns
// the path.
func writeTestKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "officer.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// claimCertTestServer serves the two claim-cert routes and verifies the
// challenge signature against pub, exactly as the ceremony service does.
func claimCertTestServer(t *testing.T, nonceHex string, pub *ecdsa.PublicKey, certPEM, caPEM string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/init/claim-cert/begin":
			var req claimCertBeginRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			respBytes, _ := json.Marshal(claimCertBeginResponse{Nonce: nonceHex})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)

		case "/api/v1/init/claim-cert/complete":
			var req claimCertCompleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if req.Username == "" || req.Nonce != nonceHex || req.Signature == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"missing fields"}`))
				return
			}
			sig, err := base64.StdEncoding.DecodeString(req.Signature)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			nonce, err := hex.DecodeString(req.Nonce)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256(nonce)
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"challenge verification failed"}`))
				return
			}
			respBytes, _ := json.Marshal(claimCertCompleteResponse{CertPEM: certPEM, CACertPEM: caPEM})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// withClaimCertFlags saves and restores every global the claim-cert command
// reads, then applies the supplied values.
func withClaimCertFlags(t *testing.T, server *httptest.Server, username, keyFile, pin, output, caOutput string) {
	t.Helper()
	oldConfig, oldFactory := globalConfig, initHTTPClientFactory
	oldUsername, oldKey, oldPin := claimCertUsername, claimCertKeyFile, claimCertSpkiPin
	oldOutput, oldCAOutput := claimCertOutput, claimCertCAOutput
	t.Cleanup(func() {
		globalConfig, initHTTPClientFactory = oldConfig, oldFactory
		claimCertUsername, claimCertKeyFile, claimCertSpkiPin = oldUsername, oldKey, oldPin
		claimCertOutput, claimCertCAOutput = oldOutput, oldCAOutput
	})

	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) { return server.Client(), nil }
	claimCertUsername, claimCertKeyFile, claimCertSpkiPin = username, keyFile, pin
	claimCertOutput, claimCertCAOutput = output, caOutput
}

func TestRunClaimCert_NoUsername(t *testing.T) {
	oldUsername := claimCertUsername
	oldPin := claimCertSpkiPin
	defer func() {
		claimCertUsername = oldUsername
		claimCertSpkiPin = oldPin
	}()

	claimCertUsername = ""
	claimCertSpkiPin = "abc123"

	err := runClaimCert(claimCertCmd, nil)
	if !errors.Is(err, ErrUsernameRequired) {
		t.Fatalf("expected ErrUsernameRequired, got: %v", err)
	}
}

// TestRunClaimCert_NoKeyFile verifies claim-cert refuses to run without the
// CSR private key: without it the challenge cannot be answered at all.
func TestRunClaimCert_NoKeyFile(t *testing.T) {
	oldUsername, oldKey, oldPin := claimCertUsername, claimCertKeyFile, claimCertSpkiPin
	defer func() {
		claimCertUsername, claimCertKeyFile, claimCertSpkiPin = oldUsername, oldKey, oldPin
	}()

	claimCertUsername = "officer-a"
	claimCertKeyFile = ""
	claimCertSpkiPin = "abc123"

	err := runClaimCert(claimCertCmd, nil)
	if !errors.Is(err, ErrKeyFileRequired) {
		t.Fatalf("expected ErrKeyFileRequired, got: %v", err)
	}
}

func TestRunClaimCert_NoSPKIPin(t *testing.T) {
	oldUsername, oldKey, oldPin := claimCertUsername, claimCertKeyFile, claimCertSpkiPin
	defer func() {
		claimCertUsername, claimCertKeyFile, claimCertSpkiPin = oldUsername, oldKey, oldPin
	}()

	claimCertUsername = "test@example.com"
	claimCertKeyFile = "/nonexistent/officer.key"
	claimCertSpkiPin = ""

	err := runClaimCert(claimCertCmd, nil)
	if !errors.Is(err, ErrSPKIPinRequired) {
		t.Fatalf("expected ErrSPKIPinRequired, got: %v", err)
	}
}

// TestRunClaimCert_UnreadableKeyFile verifies the key is loaded before any
// network round trip, so a bad path cannot burn a server-issued nonce.
func TestRunClaimCert_UnreadableKeyFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be contacted when the key file is unreadable (path %s)", r.URL.Path)
	}))
	defer server.Close()

	withClaimCertFlags(t, server, "officer-a", filepath.Join(t.TempDir(), "missing.key"), "abc123", "", "")

	err := runClaimCert(claimCertCmd, nil)
	if !errors.Is(err, ErrPrivateKeyRead) {
		t.Fatalf("expected ErrPrivateKeyRead, got: %v", err)
	}
}

// TestRunClaimCert_MalformedKeyFile verifies a non-PEM key file is rejected
// with the parse sentinel rather than panicking or reaching the server.
func TestRunClaimCert_MalformedKeyFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be contacted for a malformed key (path %s)", r.URL.Path)
	}))
	defer server.Close()

	badPath := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(badPath, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}

	withClaimCertFlags(t, server, "officer-a", badPath, "abc123", "", "")

	err := runClaimCert(claimCertCmd, nil)
	if !errors.Is(err, ErrPrivateKeyParse) {
		t.Fatalf("expected ErrPrivateKeyParse, got: %v", err)
	}
}

// TestRunClaimCert_FullProtocol drives begin then complete against a server
// that verifies the challenge signature with the CSR public key.
func TestRunClaimCert_FullProtocol(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := writeTestKeyPEM(t, key)

	nonce := hex.EncodeToString([]byte("test-nonce-12345678"))
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("officer-cert-der")}))
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("ca-cert-der")}))

	server := claimCertTestServer(t, nonce, &key.PublicKey, certPEM, caPEM)
	defer server.Close()

	withClaimCertFlags(t, server, "test@example.com", keyPath, "abc123deadbeef", "", "")

	if err := runClaimCert(claimCertCmd, nil); err != nil {
		t.Fatalf("runClaimCert failed: %v", err)
	}
}

// TestRunClaimCert_WrongKeyRejected is the regression test for the shipped
// bug: signing the challenge with a freshly generated key instead of the CSR
// key must fail, and the client must surface the server's rejection.
func TestRunClaimCert_WrongKeyRejected(t *testing.T) {
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate csr key: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	wrongKeyPath := writeTestKeyPEM(t, otherKey)

	nonce := hex.EncodeToString([]byte("test-nonce-12345678"))
	server := claimCertTestServer(t, nonce, &csrKey.PublicKey, "cert", "ca")
	defer server.Close()

	withClaimCertFlags(t, server, "test@example.com", wrongKeyPath, "abc123deadbeef", "", "")

	err = runClaimCert(claimCertCmd, nil)
	if err == nil {
		t.Fatal("expected the server to reject a signature made with a non-CSR key")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

// TestRunClaimCert_OutputToFile verifies the issued certificate and the CA
// bundle land in the requested files as PEM (not base64).
func TestRunClaimCert_OutputToFile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := writeTestKeyPEM(t, key)

	nonce := hex.EncodeToString([]byte("test-nonce-12345678"))
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("officer-cert-der")}))
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("ca-cert-der")}))

	server := claimCertTestServer(t, nonce, &key.PublicKey, certPEM, caPEM)
	defer server.Close()

	dir := t.TempDir()
	certOut := filepath.Join(dir, "claimed-cert.pem")
	caOut := filepath.Join(dir, "ca-bundle.pem")
	withClaimCertFlags(t, server, "test@example.com", keyPath, "abc123deadbeef", certOut, caOut)

	if err := runClaimCert(claimCertCmd, nil); err != nil {
		t.Fatalf("runClaimCert failed: %v", err)
	}

	written, err := os.ReadFile(certOut)
	if err != nil {
		t.Fatalf("failed to read certificate file: %v", err)
	}
	if string(written) != certPEM {
		t.Fatalf("certificate file mismatch:\ngot:  %q\nwant: %q", written, certPEM)
	}

	writtenCA, err := os.ReadFile(caOut)
	if err != nil {
		t.Fatalf("failed to read CA file: %v", err)
	}
	if string(writtenCA) != caPEM {
		t.Fatalf("CA bundle file mismatch:\ngot:  %q\nwant: %q", writtenCA, caPEM)
	}
}

func TestRunClaimCert_BeginServerError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := writeTestKeyPEM(t, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	withClaimCertFlags(t, server, "test@example.com", keyPath, "abc123", "", "")

	err = runClaimCert(claimCertCmd, nil)
	if err == nil {
		t.Fatal("expected error for server error on begin")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runClaimShare tests
//
// Share claim is a two round-trip challenge-response against
// /api/v1/init/claim-share/begin and /api/v1/init/claim-share/complete. The
// officer presents the certificate claim-cert issued them as an mTLS client
// certificate; the server binds the challenge to its thumbprint. A
// single-round-trip client would leave the server unable to bind the claim to
// anything but a username, which is the hole this flow closes.
// ---------------------------------------------------------------------------

// writeTestCertPEM writes a self-signed certificate for key and returns its
// path. It stands in for the certificate claim-cert issued the officer.
func writeTestCertPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "so@example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "officer.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

// withClaimShareFlags saves and restores every global the claim-share command
// reads, then applies the supplied values.
func withClaimShareFlags(t *testing.T, server *httptest.Server, username, certFile, keyFile, pin, output string) {
	t.Helper()
	oldConfig, oldFactory := globalConfig, initHTTPClientFactory
	oldUsername, oldPin, oldOutput := claimShareUsername, claimShareSpkiPin, claimShareOutput
	oldCert, oldKey, oldCA := claimShareCertFile, claimShareKeyFile, claimShareCAFile
	t.Cleanup(func() {
		globalConfig, initHTTPClientFactory = oldConfig, oldFactory
		claimShareUsername, claimShareSpkiPin, claimShareOutput = oldUsername, oldPin, oldOutput
		claimShareCertFile, claimShareKeyFile, claimShareCAFile = oldCert, oldKey, oldCA
	})

	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) { return server.Client(), nil }
	claimShareUsername, claimShareSpkiPin, claimShareOutput = username, pin, output
	claimShareCertFile, claimShareKeyFile, claimShareCAFile = certFile, keyFile, ""
}

// claimShareTestServer serves the two claim-share routes and verifies the
// challenge signature against pub, exactly as the ceremony service does. Every
// other path 404s, so a client that reverts to a single round trip fails.
func claimShareTestServer(t *testing.T, nonceHex string, pub *ecdsa.PublicKey, shareJSON string, seen *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/init/claim-share/begin":
			var req claimShareBeginRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			respBytes, _ := json.Marshal(claimShareBeginResponse{Nonce: nonceHex})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)

		case "/api/v1/init/claim-share/complete":
			var req claimShareCompleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if req.Nonce != nonceHex {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			sig, err := base64.StdEncoding.DecodeString(req.Signature)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			nonce, err := hex.DecodeString(req.Nonce)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			digest := sha256.Sum256(nonce)
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			respBytes, _ := json.Marshal(claimShareCompleteResponse{
				ShareIndex: 1,
				Share:      json.RawMessage(shareJSON),
			})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunClaimShare_NoUsername(t *testing.T) {
	oldUsername := claimShareUsername
	oldPin := claimShareSpkiPin
	defer func() {
		claimShareUsername = oldUsername
		claimShareSpkiPin = oldPin
	}()

	claimShareUsername = ""
	claimShareSpkiPin = "abc123"

	err := runClaimShare(claimShareCmd, nil)
	if !errors.Is(err, ErrUsernameRequired) {
		t.Fatalf("expected ErrUsernameRequired, got: %v", err)
	}
}

// TestRunClaimShare_NoCertOrKey verifies the command refuses to run without
// the officer certificate and its key: the server derives the caller
// thumbprint from the mTLS handshake, so a claim without a certificate can
// never succeed and must fail before any network round trip.
func TestRunClaimShare_NoCertOrKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyFile := writeTestKeyPEM(t, key)

	oldUsername, oldPin := claimShareUsername, claimShareSpkiPin
	oldCert, oldKey := claimShareCertFile, claimShareKeyFile
	defer func() {
		claimShareUsername, claimShareSpkiPin = oldUsername, oldPin
		claimShareCertFile, claimShareKeyFile = oldCert, oldKey
	}()

	claimShareUsername, claimShareSpkiPin = "so@example.com", "abc123"

	claimShareCertFile, claimShareKeyFile = "", keyFile
	if err := runClaimShare(claimShareCmd, nil); !errors.Is(err, ErrCertFileRequired) {
		t.Fatalf("expected ErrCertFileRequired, got: %v", err)
	}

	claimShareCertFile, claimShareKeyFile = writeTestCertPEM(t, key), ""
	if err := runClaimShare(claimShareCmd, nil); !errors.Is(err, ErrKeyFileRequired) {
		t.Fatalf("expected ErrKeyFileRequired, got: %v", err)
	}
}

func TestRunClaimShare_NoSPKIPin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	oldUsername, oldPin := claimShareUsername, claimShareSpkiPin
	oldCert, oldKey := claimShareCertFile, claimShareKeyFile
	defer func() {
		claimShareUsername, claimShareSpkiPin = oldUsername, oldPin
		claimShareCertFile, claimShareKeyFile = oldCert, oldKey
	}()

	claimShareUsername = "so@example.com"
	claimShareCertFile = writeTestCertPEM(t, key)
	claimShareKeyFile = writeTestKeyPEM(t, key)
	claimShareSpkiPin = ""

	err = runClaimShare(claimShareCmd, nil)
	if !errors.Is(err, ErrSPKIPinRequired) {
		t.Fatalf("expected ErrSPKIPinRequired, got: %v", err)
	}
}

// TestRunClaimShare_TwoRoundTrips is the regression test for the username-only
// share release: the client must complete a challenge-response, posting to
// begin and then complete. The handler 404s every other path, so a client that
// reverts to a single POST fails the test.
func TestRunClaimShare_TwoRoundTrips(t *testing.T) {
	shareJSON := `{"index":1,"value":"c2hhcmU="}`
	nonceHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var seen []string
	server := claimShareTestServer(t, nonceHex, &key.PublicKey, shareJSON, &seen)
	defer server.Close()

	withClaimShareFlags(t, server, "so@example.com",
		writeTestCertPEM(t, key), writeTestKeyPEM(t, key), "abc123deadbeef", "")

	if err := runClaimShare(claimShareCmd, nil); err != nil {
		t.Fatalf("runClaimShare failed: %v", err)
	}
	want := []string{"/api/v1/init/claim-share/begin", "/api/v1/init/claim-share/complete"}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("expected begin then complete, got %v", seen)
	}
}

// TestRunClaimShare_WrongKeyRejected verifies the client signs the nonce with
// the key it was given: a mismatched key produces a signature the server
// refuses, and no share is written.
func TestRunClaimShare_WrongKeyRejected(t *testing.T) {
	nonceHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	officerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var seen []string
	server := claimShareTestServer(t, nonceHex, &officerKey.PublicKey, `{"index":1}`, &seen)
	defer server.Close()

	// The command signs with otherKey while the server expects officerKey.
	withClaimShareFlags(t, server, "so@example.com",
		writeTestCertPEM(t, otherKey), writeTestKeyPEM(t, otherKey), "abc123deadbeef", "")

	err = runClaimShare(claimShareCmd, nil)
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError for a bad signature, got: %v", err)
	}
}

// TestRunClaimShare_OutputToFile verifies the raw share document is written
// verbatim so it can be fed straight back to an unseal command.
func TestRunClaimShare_OutputToFile(t *testing.T) {
	shareJSON := `{"index":2,"value":"c2hhcmUtdHdv"}`
	nonceHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var seen []string
	server := claimShareTestServer(t, nonceHex, &key.PublicKey, shareJSON, &seen)
	defer server.Close()

	outFile := filepath.Join(t.TempDir(), "claimed-share.json")
	withClaimShareFlags(t, server, "so@example.com",
		writeTestCertPEM(t, key), writeTestKeyPEM(t, key), "abc123deadbeef", outFile)

	if err := runClaimShare(claimShareCmd, nil); err != nil {
		t.Fatalf("runClaimShare failed: %v", err)
	}

	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(written) != shareJSON {
		t.Fatalf("share file mismatch:\ngot:  %q\nwant: %q", written, shareJSON)
	}
}

// TestRunClaimShare_EmptyShare verifies a 200 response carrying no share is
// reported as an error rather than silently writing an empty file.
func TestRunClaimShare_EmptyShare(t *testing.T) {
	nonceHex := hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/init/claim-share/begin" {
			respBytes, _ := json.Marshal(claimShareBeginResponse{Nonce: nonceHex})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	withClaimShareFlags(t, server, "so@example.com",
		writeTestCertPEM(t, key), writeTestKeyPEM(t, key), "abc123deadbeef", "")

	err = runClaimShare(claimShareCmd, nil)
	if !errors.Is(err, ErrShareMissingInResponse) {
		t.Fatalf("expected ErrShareMissingInResponse, got: %v", err)
	}
}

func TestRunClaimShare_ServerError(t *testing.T) {
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("generate key: %v", keyErr)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	withClaimShareFlags(t, server, "so@example.com",
		writeTestCertPEM(t, key), writeTestKeyPEM(t, key), "abc123", "")

	err := runClaimShare(claimShareCmd, nil)
	if err == nil {
		t.Fatal("expected error for server error")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

// TestLoadCSRPrivateKey_Encodings verifies every PEM private key encoding the
// officer might hold is accepted and round-trips through signNonce.
func TestLoadCSRPrivateKey_Encodings(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal sec1: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	tests := []struct {
		name      string
		blockType string
		der       []byte
	}{
		{"pkcs8", "PRIVATE KEY", pkcs8DER},
		{"sec1", "EC PRIVATE KEY", sec1DER},
		{"pkcs1", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: tc.blockType, Bytes: tc.der}), 0600); err != nil {
				t.Fatalf("write key: %v", err)
			}

			key, err := loadCSRPrivateKey(path)
			if err != nil {
				t.Fatalf("loadCSRPrivateKey failed: %v", err)
			}
			if _, err := signNonce([]byte("nonce"), key); err != nil {
				t.Fatalf("signNonce with loaded key failed: %v", err)
			}
		})
	}
}

// TestLoadCSRPrivateKey_Invalid verifies malformed inputs produce the typed
// parse error rather than a nil key.
func TestLoadCSRPrivateKey_Invalid(t *testing.T) {
	dir := t.TempDir()

	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("plain text"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	badDER := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("nonsense")}), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, path := range []string{notPEM, badDER} {
		if _, err := loadCSRPrivateKey(path); !errors.Is(err, ErrPrivateKeyParse) {
			t.Fatalf("expected ErrPrivateKeyParse for %s, got: %v", path, err)
		}
	}

	if _, err := loadCSRPrivateKey(filepath.Join(dir, "missing.pem")); !errors.Is(err, ErrPrivateKeyRead) {
		t.Fatalf("expected ErrPrivateKeyRead for a missing file, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runInitSignCSR tests
// ---------------------------------------------------------------------------

func TestRunInitSignCSR_NoUsername(t *testing.T) {
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldConfig := globalConfig
	defer func() {
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		globalConfig = oldConfig
	}()

	signCSRUsername = ""
	signCSRFile = "/some/csr.pem"
	signCSRRole = "admin"
	globalConfig = &Config{SOPin: "test-pin"}

	err := runInitSignCSR(initSignCSRCmd, nil)
	if !errors.Is(err, ErrUsernameRequired) {
		t.Fatalf("expected ErrUsernameRequired, got: %v", err)
	}
}

func TestRunInitSignCSR_NoCSRFile(t *testing.T) {
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldConfig := globalConfig
	defer func() {
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		globalConfig = oldConfig
	}()

	signCSRUsername = "admin-user"
	signCSRFile = ""
	signCSRRole = "admin"
	globalConfig = &Config{SOPin: "test-pin"}

	err := runInitSignCSR(initSignCSRCmd, nil)
	if !errors.Is(err, ErrCSRFileRequired) {
		t.Fatalf("expected ErrCSRFileRequired, got: %v", err)
	}
}

func TestRunInitSignCSR_NoRole(t *testing.T) {
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldConfig := globalConfig
	defer func() {
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		globalConfig = oldConfig
	}()

	signCSRUsername = "admin-user"
	signCSRFile = "/some/csr.pem"
	signCSRRole = ""
	globalConfig = &Config{SOPin: "test-pin"}

	err := runInitSignCSR(initSignCSRCmd, nil)
	if !errors.Is(err, ErrRoleRequired) {
		t.Fatalf("expected ErrRoleRequired, got: %v", err)
	}
}

func TestRunInitSignCSR_NoSOPin(t *testing.T) {
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldConfig := globalConfig
	defer func() {
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		globalConfig = oldConfig
	}()

	signCSRUsername = "admin-user"
	signCSRFile = "/some/csr.pem"
	signCSRRole = "admin"
	globalConfig = &Config{SOPin: ""}

	err := runInitSignCSR(initSignCSRCmd, nil)
	if !errors.Is(err, ErrSOPinRequired) {
		t.Fatalf("expected ErrSOPinRequired, got: %v", err)
	}
}

func TestRunInitSignCSR_BadCSRFile(t *testing.T) {
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	defer func() {
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
	}()

	signCSRUsername = "admin-user"
	signCSRFile = "/nonexistent/csr.pem"
	signCSRRole = "admin"
	globalConfig = &Config{SOPin: "test-pin", Server: "https://localhost:8443"}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return &http.Client{}, nil
	}

	err := runInitSignCSR(initSignCSRCmd, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent CSR file")
	}
	if !errors.Is(err, ErrCertFileRead) {
		t.Fatalf("expected ErrCertFileRead, got: %v", err)
	}
}

func TestRunInitSignCSR_FullProtocol(t *testing.T) {
	// Create a test CSR file.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-operator"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csrFile := filepath.Join(t.TempDir(), "test.csr")
	if err := os.WriteFile(csrFile, csrPEM, 0600); err != nil {
		t.Fatalf("failed to write CSR file: %v", err)
	}

	// Set up server that returns a signed cert.
	fakeCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake-signed-cert")})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/init/sign-csr" {
			t.Errorf("expected path /api/v1/init/sign-csr, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req signCSRInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validate request fields.
		if req.Username == "" || req.SOPin == "" || req.CSRPEM == "" || req.Role == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"missing fields"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		resp := signCSRInitResponse{CertPEM: string(fakeCertPEM)}
		respBytes, _ := json.Marshal(resp)
		_, _ = w.Write(respBytes)
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldOutput := signCSROutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		signCSROutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		SOPin:        "test-so-pin",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	signCSRUsername = "admin-user"
	signCSRFile = csrFile
	signCSRRole = "operator"
	signCSROutput = "" // stdout

	err = runInitSignCSR(initSignCSRCmd, nil)
	if err != nil {
		t.Fatalf("runInitSignCSR failed: %v", err)
	}
}

func TestRunInitSignCSR_OutputToFile(t *testing.T) {
	// Create a test CSR file.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "file-output-test"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csrFile := filepath.Join(t.TempDir(), "test.csr")
	if err := os.WriteFile(csrFile, csrPEM, 0600); err != nil {
		t.Fatalf("failed to write CSR file: %v", err)
	}

	fakeCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("signed-cert-data")})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := signCSRInitResponse{CertPEM: string(fakeCertPEM)}
		respBytes, _ := json.Marshal(resp)
		_, _ = w.Write(respBytes)
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldOutput := signCSROutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		signCSROutput = oldOutput
	}()

	outFile := filepath.Join(t.TempDir(), "signed-cert.pem")
	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		SOPin:        "test-so-pin",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	signCSRUsername = "admin-user"
	signCSRFile = csrFile
	signCSRRole = "admin"
	signCSROutput = outFile

	err = runInitSignCSR(initSignCSRCmd, nil)
	if err != nil {
		t.Fatalf("runInitSignCSR failed: %v", err)
	}

	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("output file should not be empty")
	}
	if string(written) != string(fakeCertPEM) {
		t.Fatal("output file content should match server response")
	}
}

func TestRunInitSignCSR_ServerError(t *testing.T) {
	// Create a test CSR file.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "server-error-test"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csrFile := filepath.Join(t.TempDir(), "test.csr")
	if err := os.WriteFile(csrFile, csrPEM, 0600); err != nil {
		t.Fatalf("failed to write CSR file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"SO PIN mismatch"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldOutput := signCSROutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		signCSROutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
		SOPin:        "wrong-pin",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	signCSRUsername = "admin-user"
	signCSRFile = csrFile
	signCSRRole = "admin"
	signCSROutput = ""

	err = runInitSignCSR(initSignCSRCmd, nil)
	if err == nil {
		t.Fatal("expected error for server error")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

func TestRunInitSignCSR_JSONOutput(t *testing.T) {
	// Create a test CSR file.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "json-output-test"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	csrFile := filepath.Join(t.TempDir(), "test.csr")
	if err := os.WriteFile(csrFile, csrPEM, 0600); err != nil {
		t.Fatalf("failed to write CSR file: %v", err)
	}

	fakeCertPEM := "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := signCSRInitResponse{CertPEM: fakeCertPEM}
		respBytes, _ := json.Marshal(resp)
		_, _ = w.Write(respBytes)
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := signCSRUsername
	oldCSR := signCSRFile
	oldRole := signCSRRole
	oldOutput := signCSROutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		signCSRUsername = oldUsername
		signCSRFile = oldCSR
		signCSRRole = oldRole
		signCSROutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "json",
		SOPin:        "test-so-pin",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	signCSRUsername = "admin-user"
	signCSRFile = csrFile
	signCSRRole = "admin"
	signCSROutput = "" // JSON to stdout

	err = runInitSignCSR(initSignCSRCmd, nil)
	if err != nil {
		t.Fatalf("runInitSignCSR with JSON output failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// rootCmd flag tests
// ---------------------------------------------------------------------------

func TestRootCmd_SPKIPinFlag(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("spki-pin")
	if f == nil {
		t.Fatal("expected --spki-pin persistent flag on rootCmd")
	}
}

func TestRootCmd_SOPinFlag(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("so-pin")
	if f == nil {
		t.Fatal("expected --so-pin persistent flag on rootCmd")
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// generateTempCertKeyPair generates a self-signed cert/key pair for testing.
func generateTempCertKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEMBytes, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEMBytes, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return certFile, keyFile
}
