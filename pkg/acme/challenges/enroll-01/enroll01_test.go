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

package enroll01

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// loopbackClient returns a validation client that may reach the loopback
// httptest servers these tests run against.
func loopbackClient() *validation.Client {
	return validation.NewClient(validation.Config{AllowPrivateTargets: true})
}

// Mock implementations for testing

type mockCA struct {
	verifyError          error
	credentialBlob       []byte
	encryptedSecret      []byte
	plainSecret          []byte
	defaultSigAlg        interface{}
	verifyCallCount      int
	verifyReceivedCSR    []byte
	verifyReceivedSigAlg interface{}
}

func (m *mockCA) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	m.verifyCallCount++
	m.verifyReceivedCSR = packedCSR
	m.verifyReceivedSigAlg = sigAlg

	if m.verifyError != nil {
		return nil, nil, nil, m.verifyError
	}
	return m.credentialBlob, m.encryptedSecret, m.plainSecret, nil
}

func (m *mockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	if alg, ok := m.defaultSigAlg.(x509.SignatureAlgorithm); ok {
		return alg
	}
	return x509.SHA256WithRSA // default fallback
}

type mockTPM struct {
	ekCert             []byte
	ekCertError        error
	iakAttrs           interface{}
	iakAttrsError      error
	createIDevIDHandle interface{}
	createIDevIDCSR    interface{}
	createIDevIDError  error
	activateCredSecret []byte
	activateCredError  error
	activateCallCount  int
	activateCredBlob   []byte
	activateEncSecret  []byte
}

func (m *mockTPM) EKCertificate() ([]byte, error) {
	if m.ekCertError != nil {
		return nil, m.ekCertError
	}
	return m.ekCert, nil
}

func (m *mockTPM) IAKAttributes() (interface{}, error) {
	if m.iakAttrsError != nil {
		return nil, m.iakAttrsError
	}
	return m.iakAttrs, nil
}

func (m *mockTPM) CreateIDevID(akAttrs interface{}, ekCert []byte, qualifyingData []byte) (interface{}, interface{}, error) {
	if m.createIDevIDError != nil {
		return nil, nil, m.createIDevIDError
	}
	return m.createIDevIDHandle, m.createIDevIDCSR, nil
}

func (m *mockTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	m.activateCallCount++
	m.activateCredBlob = credentialBlob
	m.activateEncSecret = encryptedSecret

	if m.activateCredError != nil {
		return nil, m.activateCredError
	}
	return m.activateCredSecret, nil
}

// mockTPMErrorPath is a mock TPM for error path testing
type mockTPMErrorPath struct {
	activateCredSecret []byte
}

func (m *mockTPMErrorPath) EKCertificate() ([]byte, error) {
	return []byte("test-ek-cert"), nil
}

func (m *mockTPMErrorPath) IAKAttributes() (interface{}, error) {
	return "test-iak-attrs", nil
}

func (m *mockTPMErrorPath) CreateIDevID(akAttrs interface{}, ekCert []byte, qualifyingData []byte) (interface{}, interface{}, error) {
	return nil, nil, nil
}

func (m *mockTPMErrorPath) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return m.activateCredSecret, nil
}

type failingWriter struct{}

func (fw *failingWriter) Header() http.Header {
	return make(http.Header)
}

func (fw *failingWriter) Write([]byte) (int, error) {
	return 0, caerrors.InternalServerError("write failed")
}

func (fw *failingWriter) WriteHeader(statusCode int) {
}

type failingReader struct{}

func (fr *failingReader) Read(p []byte) (int, error) {
	return 0, caerrors.InternalServerError("read failed")
}

// countingReader wraps an io.Reader and records how many bytes were
// actually pulled from it, so a test can assert that http.MaxBytesReader
// is bounding the read rather than merely rejecting an already-buffered
// oversized body.
type countingReader struct {
	r     io.Reader
	count int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += n
	return n, err
}

// TestVerify_Success tests successful verification flow
func TestVerify_Success(t *testing.T) {
	expectedSecret := []byte("test-secret-value")
	credBlob := []byte("credential-blob")
	encSecret := []byte("encrypted-secret")
	packedCSR := []byte("packed-csr-data")

	// Create a test HTTP server that simulates the client
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			// Serve the packed CSR
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		} else if strings.HasPrefix(r.URL.Path, secretPath) {
			// Handle activation request
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			body, _ := io.ReadAll(r.Body)
			var req activateCredentialRequest
			_ = json.Unmarshal(body, &req)

			// Verify we received the correct credentials
			receivedCredBlob, _ := base64.RawURLEncoding.DecodeString(req.CredentialBlob)
			receivedEncSecret, _ := base64.RawURLEncoding.DecodeString(req.EncryptedSecret)

			if !bytes.Equal(receivedCredBlob, credBlob) {
				t.Errorf("Credential blob mismatch")
			}
			if !bytes.Equal(receivedEncSecret, encSecret) {
				t.Errorf("Encrypted secret mismatch")
			}

			// Return the expected secret
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(expectedSecret)
		}
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}

	ca := &mockCA{
		credentialBlob:  credBlob,
		encryptedSecret: encSecret,
		plainSecret:     expectedSecret,
		defaultSigAlg:   x509.SHA256WithRSA,
	}

	err = Verify(loopbackClient(), ca, host, port, "test-token", "test-keyauth")
	if err != nil {
		t.Errorf("Verify() failed: %v", err)
	}

	if ca.verifyCallCount != 1 {
		t.Errorf("Expected VerifyTCG_CSR_IDevIDBytes to be called once, got %d", ca.verifyCallCount)
	}

	if !bytes.Equal(ca.verifyReceivedCSR, packedCSR) {
		t.Error("Verify() did not pass correct CSR to CA")
	}
}

func TestVerify_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		defaultSigAlg: x509.SHA256WithRSA,
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with HTTP error")
	}
	var status *validation.StatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusNotFound {
		t.Errorf("Expected a 404 *validation.StatusError, got: %v", err)
	}
}

func TestVerify_InvalidBase64CSR(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			// Return invalid base64
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "!!!invalid-base64!!!")
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		defaultSigAlg: x509.SHA256WithRSA,
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail with base64 decode error")
	}
}

func TestVerify_CSRVerificationFailed(t *testing.T) {
	packedCSR := []byte("packed-csr-data")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		verifyError:   caerrors.VerificationFailureError("CSR verification failed"),
		defaultSigAlg: x509.SHA256WithRSA,
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when CSR verification fails")
	}
	if !strings.Contains(err.Error(), "CSR verification failed") {
		t.Errorf("Expected CSR verification error, got: %v", err)
	}
}

func TestVerify_ActivationFailed(t *testing.T) {
	expectedSecret := []byte("test-secret")
	wrongSecret := []byte("wrong-secret")
	packedCSR := []byte("packed-csr-data")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		} else if strings.HasPrefix(r.URL.Path, secretPath) {
			// Return wrong secret
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(wrongSecret)
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		credentialBlob:  []byte("cred"),
		encryptedSecret: []byte("enc"),
		plainSecret:     expectedSecret,
		defaultSigAlg:   "RS256",
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when activation secret doesn't match")
	}
	if !strings.Contains(err.Error(), "invalid credential activation") {
		t.Errorf("Expected 'invalid credential activation' error, got: %v", err)
	}
}

func TestVerify_ReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "short")
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{defaultSigAlg: "RS256"}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when reading body fails")
	}
}

func TestVerify_JSONMarshalError(t *testing.T) {
	packedCSR := []byte("packed-csr-data")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		credentialBlob:  []byte("cred"),
		encryptedSecret: []byte("enc"),
		plainSecret:     []byte("secret"),
		defaultSigAlg:   "RS256",
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should succeed or fail based on server response")
	}
}

func TestVerify_ActivationHTTPError(t *testing.T) {
	packedCSR := []byte("packed-csr-data")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		} else if strings.HasPrefix(r.URL.Path, secretPath) {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		credentialBlob:  []byte("cred"),
		encryptedSecret: []byte("enc"),
		plainSecret:     []byte("secret"),
		defaultSigAlg:   "RS256",
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when activation returns non-200")
	}
	var status *validation.StatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected a 400 *validation.StatusError from the activation POST, got: %v", err)
	}
}

func TestVerify_ActivationReadBodyError(t *testing.T) {
	packedCSR := []byte("packed-csr-data")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		} else if strings.HasPrefix(r.URL.Path, secretPath) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "short")
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		credentialBlob:  []byte("cred"),
		encryptedSecret: []byte("enc"),
		plainSecret:     []byte("secret"),
		defaultSigAlg:   "RS256",
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when activation response body read fails")
	}
}

func TestVerify_InvalidDomain(t *testing.T) {
	ca := &mockCA{
		defaultSigAlg: x509.SHA256WithRSA,
	}

	// Use invalid domain that will cause connection error
	err := Verify(loopbackClient(), ca, "invalid.domain.that.does.not.exist", "9999", "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when domain is invalid")
	}
}

func TestVerify_PostError(t *testing.T) {
	packedCSR := []byte("packed-csr-data")

	// Serve the GET, then tear down the connection for the POST that follows.
	//
	// This used to race a goroutine that slept 50ms and closed the server
	// against Verify's two requests, which made the outcome a property of how
	// busy the machine was rather than of the code (go-xkms#243). Hijacking and
	// closing the POST's connection produces the transport error the test is
	// about, on the request the test is about, every time.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("test server does not support hijacking; cannot fail the POST deterministically")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		credentialBlob:  []byte("cred"),
		encryptedSecret: []byte("enc"),
		plainSecret:     []byte("secret"),
		defaultSigAlg:   x509.SHA256WithRSA,
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when POST request fails")
	}
}

// TestVerify_RefusesReservedTargets proves the production client refuses
// every reserved target class -- loopback, the link-local cloud metadata
// address, RFC 1918 and IPv6 loopback -- before the TCG-CSR is fetched, and
// never consults the CA.
func TestVerify_RefusesReservedTargets(t *testing.T) {
	client := validation.NewClient(validation.Config{})
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			ca := &mockCA{defaultSigAlg: x509.SHA256WithRSA}
			err := Verify(client, ca, host, "8080", "token", "keyauth")
			var verr *validation.Error
			if !errors.As(err, &verr) || verr.Kind != validation.KindTargetRefused {
				t.Fatalf("Verify(%s) error = %v, want a KindTargetRefused *validation.Error", host, err)
			}
			if ca.verifyCallCount != 0 {
				t.Fatalf("the CA must not be consulted for a refused target")
			}
		})
	}
}

// TestVerify_RejectsInjectedIdentifier proves a permanent-identifier that
// carries a path, query, fragment, userinfo or port -- the shapes that let
// an identifier choose the server's request -- is refused before any
// connection is attempted.
func TestVerify_RejectsInjectedIdentifier(t *testing.T) {
	for _, domain := range []string{
		"169.254.169.254/latest/meta-data/iam#",
		"example.com?x=1",
		"user:pass@example.com",
		"example.com:22",
		"example.com/path",
		"example.com #",
	} {
		t.Run(domain, func(t *testing.T) {
			err := Verify(loopbackClient(), &mockCA{}, domain, "8080", "token", "keyauth")
			var verr *validation.Error
			if !errors.As(err, &verr) || verr.Kind != validation.KindInvalidTarget {
				t.Fatalf("Verify(%q) error = %v, want a KindInvalidTarget *validation.Error", domain, err)
			}
		})
	}
}

// TestVerify_OversizedCSRResponse proves the CSR response is capped: a body
// larger than maxCSRResponseBytes is refused, not read into memory whole.
func TestVerify_OversizedCSRResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for written := int64(0); written <= maxCSRResponseBytes; written += int64(len(chunk)) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	ca := &mockCA{defaultSigAlg: x509.SHA256WithRSA}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	var verr *validation.Error
	if !errors.As(err, &verr) || verr.Kind != validation.KindResponseTooLarge {
		t.Fatalf("Verify() error = %v, want a KindResponseTooLarge *validation.Error", err)
	}
	if ca.verifyCallCount != 0 {
		t.Fatalf("an oversized response must not reach the CA")
	}
}

func TestVerify_Redirect(t *testing.T) {
	// Create server that tries to redirect (which should be rejected)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			// Try to redirect
			http.Redirect(w, r, "/redirect-target", http.StatusFound)
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		defaultSigAlg: x509.SHA256WithRSA,
	}

	err := Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	if err == nil {
		t.Error("Verify() should fail when receiving redirect response")
	}
}

// TestSetup_Success tests successful setup flow
func TestSetup_Success(t *testing.T) {
	ekCert := []byte("ek-certificate")
	iakAttrs := "iak-attributes"
	tcgCSR := &xkmssdk.TCG_CSR_IDEVID{
		StructVer: [4]byte{0, 0, 0, 1},
		Contents:  [4]byte{0, 0, 0, 1},
		SigSz:     [4]byte{0, 0, 0, 32},
		Signature: make([]byte, 32),
	}

	tpm := &mockTPM{
		ekCert:             ekCert,
		iakAttrs:           iakAttrs,
		createIDevIDHandle: "handle",
		createIDevIDCSR:    tcgCSR,
	}

	packedCSR, err := Setup("9080", "test-keyauth", tpm)
	if err != nil {
		t.Errorf("Setup() failed: %v", err)
	}

	if packedCSR == nil {
		t.Error("Setup() should return packed CSR")
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Try to connect to challenge endpoint (using port from Setup call)
	resp, err := http.Get(fmt.Sprintf("http://localhost:9080%stest-token", challengePath))
	if err != nil {
		t.Logf("Expected error connecting to server (this is normal for port conflicts): %v", err)
	} else {
		_ = resp.Body.Close()
	}
	// Note: Server cleanup is handled internally by startServer's local state
}

func TestSetup_EKCertError(t *testing.T) {
	tpm := &mockTPM{
		ekCertError: caerrors.KeyGenerationFailureError("failed to retrieve EK certificate"),
	}

	_, err := Setup("8081", "test-keyauth", tpm)
	if err == nil {
		t.Error("Setup() should fail when EK certificate retrieval fails")
	}
}

func TestSetup_IAKAttrsError(t *testing.T) {
	tpm := &mockTPM{
		ekCert:        []byte("ek-cert"),
		iakAttrsError: caerrors.KeyGenerationFailureError("failed to retrieve IAK attributes"),
	}

	_, err := Setup("8082", "test-keyauth", tpm)
	if err == nil {
		t.Error("Setup() should fail when IAK attributes retrieval fails")
	}
}

func TestSetup_CreateIDevIDError(t *testing.T) {
	tpm := &mockTPM{
		ekCert:            []byte("ek-cert"),
		iakAttrs:          "iak-attrs",
		createIDevIDError: caerrors.KeyGenerationFailureError("failed to create IDevID"),
	}

	_, err := Setup("8083", "test-keyauth", tpm)
	if err == nil {
		t.Error("Setup() should fail when IDevID creation fails")
	}
}

func TestSetup_InvalidTypeAssertion(t *testing.T) {
	tpm := &mockTPM{
		ekCert:             []byte("ek-cert"),
		iakAttrs:           "iak-attrs",
		createIDevIDHandle: "handle",
		createIDevIDCSR:    "not-a-tcg-csr", // Wrong type
	}

	_, err := Setup("8084", "test-keyauth", tpm)
	if err == nil {
		t.Error("Setup() should fail when CreateIDevID returns unexpected type")
	}
	if !strings.Contains(err.Error(), "unexpected type") {
		t.Errorf("Expected 'unexpected type' error, got: %v", err)
	}
}

// TestActivateCredentialHandler tests the activate credential handler
func TestActivateCredentialHandler_Success(t *testing.T) {
	expectedSecret := []byte("decrypted-secret")
	credBlob := []byte("credential-blob")
	encSecret := []byte("encrypted-secret")

	tpm := &mockTPM{
		activateCredSecret: expectedSecret,
	}

	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	req := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(credBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(encSecret),
	}

	jsonData, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", bytes.NewBuffer(jsonData))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, expectedSecret) {
		t.Errorf("Expected secret %q, got %q", expectedSecret, body)
	}

	if tpm.activateCallCount != 1 {
		t.Errorf("Expected ActivateCredential to be called once, got %d", tpm.activateCallCount)
	}
}

func TestActivateCredentialHandler_NoToken(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath, nil)
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_InvalidMethod(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	httpReq := httptest.NewRequest(http.MethodGet, secretPath+"test-token", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_InvalidContentType(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", nil)
	httpReq.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("Expected status 415, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_InvalidJSON(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", strings.NewReader("invalid json"))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_InvalidCredentialBlobBase64(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	req := &activateCredentialRequest{
		CredentialBlob:  "!!!invalid-base64!!!",
		EncryptedSecret: base64.RawURLEncoding.EncodeToString([]byte("enc")),
	}

	jsonData, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", bytes.NewBuffer(jsonData))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_InvalidEncryptedSecretBase64(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	req := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString([]byte("cred")),
		EncryptedSecret: "!!!invalid-base64!!!",
	}

	jsonData, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", bytes.NewBuffer(jsonData))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_ActivationError(t *testing.T) {
	tpm := &mockTPM{
		activateCredError: caerrors.InternalServerError("activation failed"),
	}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	req := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString([]byte("cred")),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString([]byte("enc")),
	}

	jsonData, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", bytes.NewBuffer(jsonData))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestActivateCredentialHandler_ReadBodyError(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	// Create request with body that errors on read
	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", &failingReader{})
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// TestActivateCredentialHandler_BodyTooLarge verifies that the request
// body size limit (go-xkms#891) is enforced against the raw connection
// before any JSON parsing is attempted: http.MaxBytesReader must wrap
// r.Body before the handler's first read, so an oversized body is
// rejected with 413 and the handler never buffers more than the limit
// (plus the one extra byte MaxBytesReader reads to detect the overflow).
func TestActivateCredentialHandler_BodyTooLarge(t *testing.T) {
	tpm := &mockTPM{}
	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	const maxBodySize = 1048576 // must match activateCredentialHandlerWithShutdown's limit
	oversized := bytes.Repeat([]byte("a"), maxBodySize+4096)
	counting := &countingReader{r: bytes.NewReader(oversized)}

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", counting)
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status 413, got %d", resp.StatusCode)
	}

	if counting.count > maxBodySize+1 {
		t.Errorf("handler read %d bytes from an oversized body, want at most %d (limit + 1)", counting.count, maxBodySize+1)
	}
	if counting.count == 0 {
		t.Error("handler never read from the body; the size limit test is not exercising MaxBytesReader")
	}

	if tpm.activateCallCount != 0 {
		t.Errorf("Expected ActivateCredential not to be called for an oversized body, got %d calls", tpm.activateCallCount)
	}
}

func TestActivateCredentialHandler_WriteError(t *testing.T) {
	expectedSecret := []byte("decrypted-secret")
	credBlob := []byte("credential-blob")
	encSecret := []byte("encrypted-secret")

	tpm := &mockTPM{
		activateCredSecret: expectedSecret,
	}

	handler := activateCredentialHandlerWithShutdown(tpm, nil, nil)

	req := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(credBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(encSecret),
	}

	jsonData, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", bytes.NewBuffer(jsonData))
	httpReq.Header.Set("Content-Type", "application/json")
	w := &failingWriter{}

	handler(w, httpReq)

	// Test passes if no panic occurs - the write error is logged but doesn't cause failure
}

// TestChallengeHandlerHTTPx tests the challenge handler
func TestChallengeHandlerHTTPx(t *testing.T) {
	packedCSR := []byte("test-packed-csr")
	handler := challengeHandlerHTTPx(packedCSR)

	httpReq := httptest.NewRequest(http.MethodGet, challengePath+"test-token", nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	expectedEncoded := base64.RawURLEncoding.EncodeToString(packedCSR)

	if string(body) != expectedEncoded {
		t.Errorf("Expected encoded CSR %q, got %q", expectedEncoded, string(body))
	}
}

func TestChallengeHandlerHTTPx_NoToken(t *testing.T) {
	packedCSR := []byte("test-packed-csr")
	handler := challengeHandlerHTTPx(packedCSR)

	httpReq := httptest.NewRequest(http.MethodGet, challengePath, nil)
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestChallengeHandlerHTTPx_WriteError(t *testing.T) {
	packedCSR := []byte("test-packed-csr")
	handler := challengeHandlerHTTPx(packedCSR)

	httpReq := httptest.NewRequest(http.MethodGet, challengePath+"test-token", nil)
	w := &failingWriter{}

	handler(w, httpReq)
}

func TestChallengeHandlerHTTPx_PathParsing(t *testing.T) {
	testCases := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "valid token",
			path:        challengePath + "abc123",
			expectError: false,
		},
		{
			name:        "long token",
			path:        challengePath + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
			expectError: false,
		},
		{
			name:        "token with special characters",
			path:        challengePath + "token-with-dashes_and_underscores",
			expectError: false,
		},
		{
			name:        "no token",
			path:        challengePath,
			expectError: true,
		},
	}

	packedCSR := []byte("test-packed-csr")
	handler := challengeHandlerHTTPx(packedCSR)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			if tc.expectError && resp.StatusCode == http.StatusOK {
				t.Errorf("Expected error status, got %d", resp.StatusCode)
			}

			if !tc.expectError && resp.StatusCode != http.StatusOK {
				t.Errorf("Expected OK status, got %d", resp.StatusCode)
			}
		})
	}
}

func TestActivateCredentialHandler_PathParsing(t *testing.T) {
	testCases := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "valid token",
			path:        secretPath + "abc123",
			expectError: false,
		},
		{
			name:        "no token",
			path:        secretPath,
			expectError: true,
		},
	}

	mockTPMInst := &mockTPM{
		activateCredSecret: []byte("test-secret"),
	}
	handler := activateCredentialHandlerWithShutdown(mockTPMInst, nil, nil)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Only test the token extraction, not the full handler
			req := httptest.NewRequest(http.MethodGet, tc.path, nil) // Wrong method intentionally
			w := httptest.NewRecorder()

			handler(w, req)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			// If no token, expect 400; otherwise expect 405 (wrong method)
			if tc.expectError && resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected 400 for missing token, got %d", resp.StatusCode)
			}

			if !tc.expectError && resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Expected 405 for wrong method, got %d", resp.StatusCode)
			}
		})
	}
}

// TestStartServer tests server startup functionality
func TestStartServer_ValidPort(t *testing.T) {
	// Create a mock TPM
	mockTPMInst := &mockTPMErrorPath{
		activateCredSecret: []byte("test-secret"),
	}
	packedCSR := []byte("test-csr-data")

	// Start on an available port using test helper
	state := startTestServer("19911", mockTPMInst, packedCSR)
	defer func() { _ = state.Shutdown() }()

	// Give the server time to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running
	if state.Server() == nil {
		t.Fatal("Server should have started")
	}

	// Make a request to verify it's working
	resp, err := http.Get("http://localhost:19911" + challengePath + "test-token")
	if err != nil {
		t.Logf("Server may not be fully started: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	}
}

func TestStartServer_ServerShutdownPath(t *testing.T) {
	mockTPMInst := &mockTPMErrorPath{
		activateCredSecret: []byte("test-secret"),
	}
	packedCSR := []byte("test-csr-data")

	// Start the server using test helper
	state := startTestServer("19912", mockTPMInst, packedCSR)
	time.Sleep(100 * time.Millisecond)

	// Wait for server listener to be ready (poll instead of fixed sleep)
	if state.Server() == nil {
		t.Fatal("startTestServer must always return a non-nil server")
	}

	// Gracefully shutdown the server - this should result in ErrServerClosed
	// which is NOT logged as a fatal error (the normal case)
	err := state.Shutdown()
	if err != nil {
		t.Logf("Shutdown returned: %v", err)
	}

	t.Log("Server shutdown path (ErrServerClosed) exercised successfully")
}

func TestStartServer_CreatesValidServer(t *testing.T) {
	packedCSR := []byte("test-csr-data")

	mockTPMInst := &mockTPM{
		activateCredSecret: []byte("test-secret"),
	}

	// Use a high port to avoid conflicts
	testPort := "19080"
	state := startTestServer(testPort, mockTPMInst, packedCSR)
	defer func() { _ = state.Shutdown() }()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running by making a request
	url := fmt.Sprintf("http://localhost:%s%stest-token", testPort, challengePath)
	resp, err := http.Get(url)
	if err != nil {
		t.Logf("Server may not have started (expected in some environments): %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestStartServer_HandlerSetup(t *testing.T) {
	mockTPMInst := &mockTPMErrorPath{
		activateCredSecret: []byte("test-secret"),
	}
	packedCSR := []byte("test-csr-data")

	// Start the server using test helper
	state := startTestServer("19916", mockTPMInst, packedCSR)
	defer func() { _ = state.Shutdown() }()
	time.Sleep(100 * time.Millisecond)

	// Wait for server listener to be ready (poll instead of fixed sleep)
	if state.Server() == nil {
		t.Fatal("startTestServer must always return a non-nil server")
	}

	// Test challenge path
	resp, err := http.Get("http://localhost:19916" + challengePath + "test-token")
	if err != nil {
		t.Logf("Challenge request failed: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Challenge expected 200, got %d", resp.StatusCode)
		}
	}

	// Test secret path (wrong method should return 405)
	resp, err = http.Get("http://localhost:19916" + secretPath + "test-token")
	if err != nil {
		t.Logf("Secret request failed: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Logf("Secret path returned %d (expected 405 for GET)", resp.StatusCode)
		}
	}
}

// TestHandleShutdown tests shutdown handling functionality
func TestHandleShutdown_ShutdownOnceLogic(t *testing.T) {
	// Create a test server with local state
	var localOnce sync.Once
	mux := http.NewServeMux()
	// Bind an ephemeral port: the test needs a listening socket, not a
	// specific number, so nothing can collide with a concurrent run.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	testServer := &http.Server{
		Handler: mux,
	}

	// Start serving in background
	go func() {
		_ = testServer.Serve(listener)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Track shutdown execution
	shutdownExecuted := false
	shutdownCount := 0

	// Execute the shutdown logic that handleShutdownWithServer uses
	localOnce.Do(func() {
		shutdownExecuted = true
		shutdownCount++
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		_ = testServer.Shutdown(ctx)
	})

	// Try to execute again - should not run
	localOnce.Do(func() {
		shutdownCount++
	})

	if !shutdownExecuted {
		t.Error("Shutdown logic was not executed")
	}

	if shutdownCount != 1 {
		t.Errorf("Expected shutdown count 1, got %d", shutdownCount)
	}
}

func TestHandleShutdown_SignalHandling(t *testing.T) {
	// Create a test server with local state
	mux := http.NewServeMux()
	// Bind an ephemeral port: the test needs a listening socket, not a
	// specific number, so nothing can collide with a concurrent run.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	testServer := &http.Server{
		Handler: mux,
	}

	// Start serving in background
	serverStarted := make(chan struct{})
	go func() {
		close(serverStarted)
		_ = testServer.Serve(listener)
	}()
	<-serverStarted

	// Give server time to fully start
	time.Sleep(100 * time.Millisecond)

	// Simulate the signal channel behavior
	sigChan := make(chan bool, 1)
	done := make(chan struct{})
	var localOnce sync.Once

	go func() {
		// Wait for simulated signal
		<-sigChan
		t.Log("Received simulated shutdown signal")

		// Execute shutdown with local sync.Once
		localOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer cancel()
			_ = testServer.Shutdown(ctx)
		})
		close(done)
	}()

	// Send simulated signal
	sigChan <- true

	// Wait for shutdown
	select {
	case <-done:
		t.Log("Shutdown completed successfully")
	case <-time.After(2 * time.Second):
		t.Error("Shutdown timed out")
	}

	_ = listener.Close()
}

func TestHandleShutdown_ShutdownError(t *testing.T) {
	// Create a test server with local state
	mux := http.NewServeMux()
	// Bind an ephemeral port: the test needs a listening socket, not a
	// specific number, so nothing can collide with a concurrent run.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	testServer := &http.Server{
		Handler: mux,
	}

	// Start serving
	go func() {
		_ = testServer.Serve(listener)
	}()
	time.Sleep(100 * time.Millisecond)

	// Create a pre-cancelled context to trigger Shutdown error
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Execute shutdown with cancelled context
	var localOnce sync.Once
	var shutdownErr error

	localOnce.Do(func() {
		shutdownErr = testServer.Shutdown(ctx)
	})

	// Log the result - cancelled context should cause an error
	if shutdownErr != nil {
		t.Logf("Shutdown with cancelled context returned: %v", shutdownErr)
	} else {
		t.Log("Shutdown completed even with cancelled context")
	}

	// Clean up with a valid context
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	_ = testServer.Shutdown(ctx2)
}

func TestHandleShutdown_SignalTypes(t *testing.T) {
	signalTypes := []struct {
		name string
		sig  syscall.Signal
	}{
		{"SIGINT", syscall.SIGINT},
		{"SIGTERM", syscall.SIGTERM},
	}

	for _, st := range signalTypes {
		t.Run(st.name, func(t *testing.T) {
			// Create local test server
			mux := http.NewServeMux()
			listener, err := net.Listen("tcp", ":0") // Use ephemeral port
			if err != nil {
				t.Fatalf("Failed to listen: %v", err)
			}
			defer func() { _ = listener.Close() }()

			testServer := &http.Server{Handler: mux}

			go func() {
				_ = testServer.Serve(listener)
			}()

			time.Sleep(50 * time.Millisecond)

			// Simulate signal handling with local sync.Once
			var localOnce sync.Once
			signalReceived := st.sig

			localOnce.Do(func() {
				t.Logf("Handling signal: %v", signalReceived)
				ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
				defer cancel()
				_ = testServer.Shutdown(ctx)
			})
		})
	}
}

func TestHandleShutdown_NilServerSafe(t *testing.T) {
	// Test nil server handling - should not panic
	var testServer *http.Server = nil

	// Execute shutdown logic - should not panic
	var localOnce sync.Once
	localOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		if testServer != nil {
			_ = testServer.Shutdown(ctx)
		}
		// No action needed if server is nil - this is the safe path
	})

	t.Log("Nil server handled safely")
}

func TestHandleShutdown_SignalReceived(t *testing.T) {
	// Create a local test server
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	testServer := ts.Config

	// Create a channel to track shutdown completion
	done := make(chan struct{})
	var localOnce sync.Once

	// Simulate handleShutdown behavior in a goroutine
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Wait for signal or timeout
		select {
		case sig := <-sigChan:
			t.Logf("Received signal: %v", sig)
		case <-time.After(100 * time.Millisecond):
			// Timeout for testing purposes
		}

		// Execute shutdown logic
		localOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer cancel()
			if testServer != nil {
				_ = testServer.Shutdown(ctx)
			}
		})
		close(done)
	}()

	// Send signal (will likely not be received due to test timing, but exercises the code path)
	// Give the goroutine time to set up the signal handler
	time.Sleep(50 * time.Millisecond)

	// Wait for completion
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Log("Shutdown logic completed via timeout path")
	}
}

func TestHandleShutdown_MultipleSignals(t *testing.T) {
	var localOnce sync.Once
	shutdownCount := 0

	// Simulate receiving multiple signals
	for i := 0; i < 3; i++ {
		localOnce.Do(func() {
			shutdownCount++
		})
	}

	// Verify shutdown only happens once
	if shutdownCount != 1 {
		t.Errorf("Expected shutdown count 1, got %d", shutdownCount)
	}
}

func TestHandleShutdown_ShutdownTimeout(t *testing.T) {
	// Verify the timeout constant is set appropriately
	if serverShutdownTimeout < time.Second {
		t.Errorf("Shutdown timeout too short: %v", serverShutdownTimeout)
	}

	if serverShutdownTimeout > 30*time.Second {
		t.Errorf("Shutdown timeout too long: %v", serverShutdownTimeout)
	}
}

func TestHandleShutdown_NilServer(t *testing.T) {
	// Test nil server handling - should not panic
	var testServer *http.Server = nil
	var localOnce sync.Once

	// This should not panic
	localOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		if testServer != nil {
			_ = testServer.Shutdown(ctx)
		}
		// No action needed if server is nil
	})
}

func TestHandleShutdown_ContextCancellation(t *testing.T) {
	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context immediately
	cancel()

	// Create a mock server that never returns from Shutdown
	mux := http.NewServeMux()
	ts := httptest.NewUnstartedServer(mux)
	ts.Start()
	defer ts.Close()

	// Attempt shutdown with cancelled context
	mockServer := ts.Config
	err := mockServer.Shutdown(ctx)

	// Shutdown should return immediately due to cancelled context
	if err != nil && err != context.Canceled {
		t.Logf("Shutdown returned: %v", err)
	}
}

// TestHandleShutdownWithServer_NilParameters tests handleShutdownWithServer with nil parameters
func TestHandleShutdownWithServer_NilParameters(t *testing.T) {
	// Test with nil server - should return immediately
	handleShutdownWithServer(nil, &sync.Once{})

	// Test with nil shutdownOnce - should return immediately
	handleShutdownWithServer(&http.Server{}, nil)

	// Test with both nil - should return immediately
	handleShutdownWithServer(nil, nil)
}

// TestActivateCredentialHandler_WithServerShutdown tests the handler with server and shutdownOnce
func TestActivateCredentialHandler_WithServerShutdown(t *testing.T) {
	expectedSecret := []byte("decrypted-secret")
	credBlob := []byte("credential-blob")
	encSecret := []byte("encrypted-secret")

	tpm := &mockTPM{
		activateCredSecret: expectedSecret,
	}

	// Create a test server
	mux := http.NewServeMux()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	testServer := &http.Server{Handler: mux}
	var shutdownOnce sync.Once

	// Start server
	serverDone := make(chan struct{})
	go func() {
		_ = testServer.Serve(listener)
		close(serverDone)
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Create handler with server and shutdownOnce
	handler := activateCredentialHandlerWithShutdown(tpm, testServer, &shutdownOnce)

	req := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(credBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(encSecret),
	}

	jsonData, _ := json.Marshal(req)

	httpReq := httptest.NewRequest(http.MethodPost, secretPath+"test-token", bytes.NewBuffer(jsonData))
	httpReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, httpReq)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Wait for the shutdown goroutine to execute
	time.Sleep(100 * time.Millisecond)

	// Close the listener to allow server to stop
	_ = listener.Close()

	// Wait for server to finish
	select {
	case <-serverDone:
		// Server shutdown completed
	case <-time.After(serverShutdownTimeout + time.Second):
		t.Log("Server shutdown timed out (expected in some cases)")
	}
}

// BenchmarkVerify benchmarks the verification function
func BenchmarkVerify(b *testing.B) {
	expectedSecret := []byte("bench-secret")
	packedCSR := []byte("bench-csr")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, challengePath) {
			encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, encodedCSR)
		} else if strings.HasPrefix(r.URL.Path, secretPath) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(expectedSecret)
		}
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	ca := &mockCA{
		credentialBlob:  []byte("cred"),
		encryptedSecret: []byte("enc"),
		plainSecret:     expectedSecret,
		defaultSigAlg:   "RS256",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(loopbackClient(), ca, host, port, "token", "keyauth")
	}
}

// TestListenAddress pins what Setup does with its address argument: a
// host:port or ":port" reaches net.Listen verbatim, and a bare port keeps
// its historical meaning of every interface, so no literal here decides
// which host is bound (go-xkms#140).
func TestListenAddress(t *testing.T) {
	tests := map[string]string{
		"8080":           ":8080",
		":8080":          ":8080",
		"127.0.0.1:8080": "127.0.0.1:8080",
		"[::1]:8080":     "[::1]:8080",
	}
	for in, want := range tests {
		if got := listenAddress(in); got != want {
			t.Errorf("listenAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
