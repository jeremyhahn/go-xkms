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
// generateNoiseKeyPair tests
// ---------------------------------------------------------------------------

func TestGenerateNoiseKeyPair_Success(t *testing.T) {
	pubKey, privKey, err := generateNoiseKeyPair()
	if err != nil {
		t.Fatalf("generateNoiseKeyPair failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("public key should not be empty")
	}
	if privKey == nil {
		t.Fatal("private key should not be nil")
	}

	// Verify the returned private key is ECDSA P-256
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("expected *ecdsa.PrivateKey")
	}
	if ecKey.Curve != elliptic.P256() {
		t.Fatal("expected P-256 curve")
	}

	// Verify the public key bytes can be parsed back
	parsed, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to parse public key bytes: %v", err)
	}
	_, ok = parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("parsed key should be *ecdsa.PublicKey")
	}
}

func TestGenerateNoiseKeyPair_SignNonceRoundtrip(t *testing.T) {
	pubKey, privKey, err := generateNoiseKeyPair()
	if err != nil {
		t.Fatalf("generateNoiseKeyPair failed: %v", err)
	}

	nonce := []byte("roundtrip-nonce")
	sig, err := signNonce(nonce, privKey)
	if err != nil {
		t.Fatalf("signNonce failed: %v", err)
	}

	// Verify using the public key bytes
	parsed, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	ecPub := parsed.(*ecdsa.PublicKey)
	hash := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(ecPub, hash[:], sig) {
		t.Fatal("signature verification failed on roundtrip")
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
	// InsecureSkipVerify must be true because this is trust bootstrap mode:
	// no CA cert available, SPKI pin verification via VerifyConnection IS the security.
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify=true for SPKI bootstrap (CA chain skipped, pin verified)")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("expected VerifyConnection callback to be set for SPKI pin verification")
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
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("expected MinVersion TLS 1.2")
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
	flags := []string{"username", "spki-pin", "output"}
	for _, name := range flags {
		f := claimCertCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag --%s on claim-cert command", name)
		}
	}
}

func TestClaimShareCmd_Flags(t *testing.T) {
	flags := []string{"username", "spki-pin", "output"}
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

func TestRunClaimCert_NoSPKIPin(t *testing.T) {
	oldUsername := claimCertUsername
	oldPin := claimCertSpkiPin
	defer func() {
		claimCertUsername = oldUsername
		claimCertSpkiPin = oldPin
	}()

	claimCertUsername = "test@example.com"
	claimCertSpkiPin = ""

	err := runClaimCert(claimCertCmd, nil)
	if !errors.Is(err, ErrSPKIPinRequired) {
		t.Fatalf("expected ErrSPKIPinRequired, got: %v", err)
	}
}

func TestRunClaimCert_FullProtocol(t *testing.T) {
	// Set up a test server that handles the full begin/complete protocol
	nonce := hex.EncodeToString([]byte("test-nonce-12345678"))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake-cert-der")})
	certB64 := base64.StdEncoding.EncodeToString(certPEM)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/init/claim-cert/begin":
			var req claimCertBeginRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			resp := claimCertBeginResponse{Nonce: nonce}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)

		case "/api/v1/init/claim-cert/complete":
			var req claimCertCompleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Verify required fields are present
			if req.Username == "" || req.Nonce == "" || req.PublicKey == "" || req.Signature == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"missing fields"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			resp := claimCertCompleteResponse{Certificate: certB64}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := claimCertUsername
	oldPin := claimCertSpkiPin
	oldOutput := claimCertOutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		claimCertUsername = oldUsername
		claimCertSpkiPin = oldPin
		claimCertOutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	claimCertUsername = "test@example.com"
	claimCertSpkiPin = "abc123deadbeef"
	claimCertOutput = "" // print to stdout

	err := runClaimCert(claimCertCmd, nil)
	if err != nil {
		t.Fatalf("runClaimCert failed: %v", err)
	}
}

func TestRunClaimCert_OutputToFile(t *testing.T) {
	nonce := hex.EncodeToString([]byte("test-nonce-12345678"))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake-cert-der")})
	certB64 := base64.StdEncoding.EncodeToString(certPEM)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/init/claim-cert/begin":
			w.WriteHeader(http.StatusOK)
			resp := claimCertBeginResponse{Nonce: nonce}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)
		case "/api/v1/init/claim-cert/complete":
			w.WriteHeader(http.StatusOK)
			resp := claimCertCompleteResponse{Certificate: certB64}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := claimCertUsername
	oldPin := claimCertSpkiPin
	oldOutput := claimCertOutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		claimCertUsername = oldUsername
		claimCertSpkiPin = oldPin
		claimCertOutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	outFile := filepath.Join(t.TempDir(), "claimed-cert.pem")
	claimCertUsername = "test@example.com"
	claimCertSpkiPin = "abc123deadbeef"
	claimCertOutput = outFile

	err := runClaimCert(claimCertCmd, nil)
	if err != nil {
		t.Fatalf("runClaimCert failed: %v", err)
	}

	// Verify file was written
	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("output file should not be empty")
	}
}

func TestRunClaimCert_BeginServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := claimCertUsername
	oldPin := claimCertSpkiPin
	oldOutput := claimCertOutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		claimCertUsername = oldUsername
		claimCertSpkiPin = oldPin
		claimCertOutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	claimCertUsername = "test@example.com"
	claimCertSpkiPin = "abc123"
	claimCertOutput = ""

	err := runClaimCert(claimCertCmd, nil)
	if err == nil {
		t.Fatal("expected error for server error on begin")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runClaimShare tests
// ---------------------------------------------------------------------------

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

func TestRunClaimShare_NoSPKIPin(t *testing.T) {
	oldUsername := claimShareUsername
	oldPin := claimShareSpkiPin
	defer func() {
		claimShareUsername = oldUsername
		claimShareSpkiPin = oldPin
	}()

	claimShareUsername = "so@example.com"
	claimShareSpkiPin = ""

	err := runClaimShare(claimShareCmd, nil)
	if !errors.Is(err, ErrSPKIPinRequired) {
		t.Fatalf("expected ErrSPKIPinRequired, got: %v", err)
	}
}

func TestRunClaimShare_FullProtocol(t *testing.T) {
	nonce := hex.EncodeToString([]byte("share-nonce-data"))
	sharePEM := pem.EncodeToMemory(&pem.Block{Type: "SHARE", Bytes: []byte("fake-share-data")})
	shareB64 := base64.StdEncoding.EncodeToString(sharePEM)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/init/claim-share/begin":
			w.WriteHeader(http.StatusOK)
			resp := claimShareBeginResponse{Nonce: nonce}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)

		case "/api/v1/init/claim-share/complete":
			var req claimShareCompleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if req.Username == "" || req.Nonce == "" || req.PublicKey == "" || req.Signature == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"missing fields"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			resp := claimShareCompleteResponse{
				Share:      shareB64,
				ShareIndex: 1,
				Threshold:  3,
			}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := claimShareUsername
	oldPin := claimShareSpkiPin
	oldOutput := claimShareOutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		claimShareUsername = oldUsername
		claimShareSpkiPin = oldPin
		claimShareOutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	claimShareUsername = "so@example.com"
	claimShareSpkiPin = "abc123deadbeef"
	claimShareOutput = "" // print to stdout

	err := runClaimShare(claimShareCmd, nil)
	if err != nil {
		t.Fatalf("runClaimShare failed: %v", err)
	}
}

func TestRunClaimShare_OutputToFile(t *testing.T) {
	nonce := hex.EncodeToString([]byte("share-nonce-data"))
	sharePEM := pem.EncodeToMemory(&pem.Block{Type: "SHARE", Bytes: []byte("fake-share-data")})
	shareB64 := base64.StdEncoding.EncodeToString(sharePEM)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/init/claim-share/begin":
			w.WriteHeader(http.StatusOK)
			resp := claimShareBeginResponse{Nonce: nonce}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)
		case "/api/v1/init/claim-share/complete":
			w.WriteHeader(http.StatusOK)
			resp := claimShareCompleteResponse{
				Share:      shareB64,
				ShareIndex: 2,
				Threshold:  5,
			}
			respBytes, _ := json.Marshal(resp)
			_, _ = w.Write(respBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := claimShareUsername
	oldPin := claimShareSpkiPin
	oldOutput := claimShareOutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		claimShareUsername = oldUsername
		claimShareSpkiPin = oldPin
		claimShareOutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	outFile := filepath.Join(t.TempDir(), "claimed-share.pem")
	claimShareUsername = "so@example.com"
	claimShareSpkiPin = "abc123deadbeef"
	claimShareOutput = outFile

	err := runClaimShare(claimShareCmd, nil)
	if err != nil {
		t.Fatalf("runClaimShare failed: %v", err)
	}

	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("output file should not be empty")
	}
}

func TestRunClaimShare_BeginServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()

	oldConfig := globalConfig
	oldFactory := initHTTPClientFactory
	oldUsername := claimShareUsername
	oldPin := claimShareSpkiPin
	oldOutput := claimShareOutput
	defer func() {
		globalConfig = oldConfig
		initHTTPClientFactory = oldFactory
		claimShareUsername = oldUsername
		claimShareSpkiPin = oldPin
		claimShareOutput = oldOutput
	}()

	globalConfig = &Config{
		Server:       server.URL,
		OutputFormat: "text",
	}
	initHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}

	claimShareUsername = "so@example.com"
	claimShareSpkiPin = "abc123"
	claimShareOutput = ""

	err := runClaimShare(claimShareCmd, nil)
	if err == nil {
		t.Fatal("expected error for server error on begin")
	}
	if !errors.Is(err, ErrServerResponseError) {
		t.Fatalf("expected ErrServerResponseError, got: %v", err)
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
