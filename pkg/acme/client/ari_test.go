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

package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// TestARIGetCertificateID tests the GetCertificateID function
func TestARIGetCertificateID(t *testing.T) {
	t.Run("valid certificate with AKI", func(t *testing.T) {
		cert := createTestCertificateWithAKI(t)
		certID := GetCertificateID(cert)

		if certID == "" {
			t.Fatal("expected non-empty certificate ID")
		}

		// Verify the ID contains a dot separator
		if len(certID) < 3 {
			t.Fatalf("certificate ID too short: %s", certID)
		}

		// Parse it back to verify format
		aki, serial, err := ParseCertificateID(certID)
		if err != nil {
			t.Fatalf("failed to parse certificate ID: %v", err)
		}

		if len(aki) == 0 {
			t.Error("parsed AKI is empty")
		}

		if len(serial) == 0 {
			t.Error("parsed serial is empty")
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		certID := GetCertificateID(nil)
		if certID != "" {
			t.Errorf("expected empty certificate ID for nil cert, got: %s", certID)
		}
	})

	t.Run("certificate without AKI", func(t *testing.T) {
		cert := createTestCertificateWithoutAKI(t)
		certID := GetCertificateID(cert)

		if certID != "" {
			t.Errorf("expected empty certificate ID for cert without AKI, got: %s", certID)
		}
	})
}

// TestARIGetCertificateIDFromHash tests the GetCertificateIDFromHash function
func TestARIGetCertificateIDFromHash(t *testing.T) {
	t.Run("valid certificate", func(t *testing.T) {
		cert := createTestCertificateWithoutAKI(t)
		certID := GetCertificateIDFromHash(cert)

		if certID == "" {
			t.Fatal("expected non-empty certificate ID from hash")
		}

		// Should be truncated to 32 chars
		if len(certID) > 32 {
			t.Errorf("expected certificate ID <= 32 chars, got %d", len(certID))
		}
	})

	t.Run("nil certificate", func(t *testing.T) {
		certID := GetCertificateIDFromHash(nil)
		if certID != "" {
			t.Errorf("expected empty certificate ID for nil cert, got: %s", certID)
		}
	})

	t.Run("certificate with empty Raw bytes", func(t *testing.T) {
		// A non-nil certificate whose Raw field was never populated (e.g.
		// constructed directly rather than parsed) has nothing to hash.
		certID := GetCertificateIDFromHash(&x509.Certificate{})
		if certID != "" {
			t.Errorf("expected empty certificate ID for cert with empty Raw, got: %s", certID)
		}
	})
}

// TestARIParseCertificateID tests the ParseCertificateID function
func TestARIParseCertificateID(t *testing.T) {
	t.Run("valid certificate ID", func(t *testing.T) {
		// Create a valid certificate ID from a test certificate
		cert := createTestCertificateWithAKI(t)
		certID := GetCertificateID(cert)

		aki, serial, err := ParseCertificateID(certID)
		if err != nil {
			t.Fatalf("failed to parse valid certificate ID: %v", err)
		}

		if len(aki) == 0 {
			t.Error("AKI should not be empty")
		}

		if len(serial) == 0 {
			t.Error("serial should not be empty")
		}
	})

	t.Run("empty certificate ID", func(t *testing.T) {
		_, _, err := ParseCertificateID("")
		if err == nil {
			t.Error("expected error for empty certificate ID")
		}
	})

	t.Run("invalid format - no dot", func(t *testing.T) {
		_, _, err := ParseCertificateID("invalidformat")
		if err == nil {
			t.Error("expected error for certificate ID without dot")
		}
	})

	t.Run("invalid format - too many dots", func(t *testing.T) {
		_, _, err := ParseCertificateID("a.b.c")
		if err == nil {
			t.Error("expected error for certificate ID with too many dots")
		}
	})

	t.Run("invalid base64 in AKI", func(t *testing.T) {
		_, _, err := ParseCertificateID("!!!invalid!!!.YWJj")
		if err == nil {
			t.Error("expected error for invalid AKI encoding")
		}
	})

	t.Run("invalid base64 in serial", func(t *testing.T) {
		_, _, err := ParseCertificateID("YWJj.!!!invalid!!!")
		if err == nil {
			t.Error("expected error for invalid serial encoding")
		}
	})
}

// TestARIValidateCertificateID tests the ValidateCertificateID function
func TestARIValidateCertificateID(t *testing.T) {
	t.Run("valid ID", func(t *testing.T) {
		cert := createTestCertificateWithAKI(t)
		certID := GetCertificateID(cert)

		err := ValidateCertificateID(certID)
		if err != nil {
			t.Errorf("expected valid certificate ID, got error: %v", err)
		}
	})

	t.Run("invalid ID", func(t *testing.T) {
		err := ValidateCertificateID("")
		if err == nil {
			t.Error("expected error for empty certificate ID")
		}
	})
}

// TestARIBuildRenewalInfoURL tests the BuildRenewalInfoURL function
func TestARIBuildRenewalInfoURL(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		baseURL := "https://acme.example.com/renewalInfo"
		certID := "YWJjZGVm.MTIzNDU2"

		url, err := BuildRenewalInfoURL(baseURL, certID)
		if err != nil {
			t.Fatalf("failed to build URL: %v", err)
		}

		expected := "https://acme.example.com/renewalInfo/YWJjZGVm.MTIzNDU2"
		if url != expected {
			t.Errorf("expected %s, got %s", expected, url)
		}
	})

	t.Run("base URL with trailing slash", func(t *testing.T) {
		baseURL := "https://acme.example.com/renewalInfo/"
		certID := "YWJjZGVm.MTIzNDU2"

		url, err := BuildRenewalInfoURL(baseURL, certID)
		if err != nil {
			t.Fatalf("failed to build URL: %v", err)
		}

		expected := "https://acme.example.com/renewalInfo/YWJjZGVm.MTIzNDU2"
		if url != expected {
			t.Errorf("expected %s, got %s", expected, url)
		}
	})

	t.Run("empty base URL", func(t *testing.T) {
		_, err := BuildRenewalInfoURL("", "YWJjZGVm.MTIzNDU2")
		if err == nil {
			t.Error("expected error for empty base URL")
		}
	})

	t.Run("empty certificate ID", func(t *testing.T) {
		_, err := BuildRenewalInfoURL("https://acme.example.com/renewalInfo", "")
		if err == nil {
			t.Error("expected error for empty certificate ID")
		}
	})
}

// TestARIRenewalInfoShouldRenewNow tests the ShouldRenewNow method
func TestARIRenewalInfoShouldRenewNow(t *testing.T) {
	t.Run("window started in past", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(-24 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(24 * time.Hour)

		if !ri.ShouldRenewNow() {
			t.Error("should renew when window has started")
		}
	})

	t.Run("window starts now", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now()
		ri.SuggestedWindow.End = time.Now().Add(24 * time.Hour)

		if !ri.ShouldRenewNow() {
			t.Error("should renew when window starts now")
		}
	})

	t.Run("window in future", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(24 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(48 * time.Hour)

		if ri.ShouldRenewNow() {
			t.Error("should not renew when window is in future")
		}
	})

	t.Run("nil renewal info", func(t *testing.T) {
		var ri *RenewalInfo
		if ri.ShouldRenewNow() {
			t.Error("nil renewal info should return false")
		}
	})
}

// TestARIRenewalInfoShouldRenewSoon tests the ShouldRenewSoon method
func TestARIRenewalInfoShouldRenewSoon(t *testing.T) {
	t.Run("within threshold", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(12 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(36 * time.Hour)

		if !ri.ShouldRenewSoon(24 * time.Hour) {
			t.Error("should renew soon when within threshold")
		}
	})

	t.Run("outside threshold", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(48 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(72 * time.Hour)

		if ri.ShouldRenewSoon(24 * time.Hour) {
			t.Error("should not renew soon when outside threshold")
		}
	})

	t.Run("nil renewal info", func(t *testing.T) {
		var ri *RenewalInfo
		if ri.ShouldRenewSoon(24 * time.Hour) {
			t.Error("nil renewal info should return false")
		}
	})
}

// TestARIRenewalInfoRandomRenewalTime tests the RandomRenewalTime method
func TestARIRenewalInfoRandomRenewalTime(t *testing.T) {
	t.Run("valid window", func(t *testing.T) {
		ri := &RenewalInfo{}
		start := time.Now()
		end := start.Add(24 * time.Hour)
		ri.SuggestedWindow.Start = start
		ri.SuggestedWindow.End = end

		renewTime := ri.RandomRenewalTime()

		if renewTime.Before(start) || renewTime.After(end) {
			t.Errorf("renewal time %v should be within window [%v, %v]", renewTime, start, end)
		}
	})

	t.Run("invalid window - end before start", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(24 * time.Hour)
		ri.SuggestedWindow.End = time.Now()

		renewTime := ri.RandomRenewalTime()

		if !renewTime.Equal(ri.SuggestedWindow.Start) {
			t.Error("should return start time for invalid window")
		}
	})

	t.Run("nil renewal info", func(t *testing.T) {
		var ri *RenewalInfo
		renewTime := ri.RandomRenewalTime()

		if !renewTime.IsZero() {
			t.Error("nil renewal info should return zero time")
		}
	})
}

// TestARIRenewalInfoHasExplanation tests the HasExplanation method
func TestARIRenewalInfoHasExplanation(t *testing.T) {
	t.Run("with explanation URL", func(t *testing.T) {
		ri := &RenewalInfo{
			ExplanationURL: "https://example.com/explanation",
		}

		if !ri.HasExplanation() {
			t.Error("should return true when explanation URL is present")
		}
	})

	t.Run("without explanation URL", func(t *testing.T) {
		ri := &RenewalInfo{}

		if ri.HasExplanation() {
			t.Error("should return false when explanation URL is empty")
		}
	})

	t.Run("nil renewal info", func(t *testing.T) {
		var ri *RenewalInfo
		if ri.HasExplanation() {
			t.Error("nil renewal info should return false")
		}
	})
}

// TestARIGetRenewalInfo tests the GetRenewalInfo client method
func TestARIGetRenewalInfo(t *testing.T) {
	t.Run("successful fetch", func(t *testing.T) {
		// Create mock server
		startTime := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
		endTime := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

		renewalInfoHandler := func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("expected GET, got %s", r.Method)
			}

			response := map[string]interface{}{
				"suggestedWindow": map[string]string{
					"start": startTime.Format(time.RFC3339),
					"end":   endTime.Format(time.RFC3339),
				},
				"explanationURL": "https://example.com/explain",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}

		directoryHandler := func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/directory", directoryHandler)
		mux.HandleFunc("/renewalInfo/", renewalInfoHandler)

		server := httptest.NewServer(mux)
		defer server.Close()

		// Create client with mock directory
		client := createTestARIClient(t, server.URL+"/directory", server.URL+"/renewalInfo")

		ri, err := client.GetRenewalInfo(context.Background(), "YWJj.MTIz")
		if err != nil {
			t.Fatalf("failed to get renewal info: %v", err)
		}

		if !ri.SuggestedWindow.Start.Equal(startTime) {
			t.Errorf("expected start time %v, got %v", startTime, ri.SuggestedWindow.Start)
		}

		if !ri.SuggestedWindow.End.Equal(endTime) {
			t.Errorf("expected end time %v, got %v", endTime, ri.SuggestedWindow.End)
		}

		if ri.ExplanationURL != "https://example.com/explain" {
			t.Errorf("expected explanation URL, got %s", ri.ExplanationURL)
		}
	})

	t.Run("empty certificate ID", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		defer server.Close()

		client := createTestARIClient(t, server.URL+"/directory", server.URL+"/renewalInfo")

		_, err := client.GetRenewalInfo(context.Background(), "")
		if err == nil {
			t.Error("expected error for empty certificate ID")
		}
	})

	t.Run("server error", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/directory" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"renewalInfo": r.Host + "/renewalInfo",
				})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   ErrTypeServerInternal,
				"detail": "internal error",
				"status": 500,
			})
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClient(t, server.URL+"/directory", server.URL+"/renewalInfo")

		_, err := client.GetRenewalInfo(context.Background(), "YWJj.MTIz")
		if err == nil {
			t.Error("expected error for server error response")
		}
	})

	t.Run("server error with unreadable body", func(t *testing.T) {
		// Declaring a larger Content-Length than actually written causes
		// io.ReadAll(resp.Body) to fail with an unexpected EOF once the
		// server closes the connection, without any permission tricks.
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/directory" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"renewalInfo": r.Host + "/renewalInfo",
				})
				return
			}
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("short"))
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClient(t, server.URL+"/directory", server.URL+"/renewalInfo")
		var logBuf bytes.Buffer
		client.logger = slog.New(slog.NewTextHandler(&logBuf, nil))

		_, err := client.GetRenewalInfo(context.Background(), "YWJj.MTIz")
		if err == nil {
			t.Fatal("expected error for server error response")
		}
		// The failure to read the diagnostic body is itself reported, not
		// silently dropped.
		if !strings.Contains(logBuf.String(), "bodyReadError") {
			t.Errorf("expected bodyReadError to be logged, got: %s", logBuf.String())
		}
	})
}

// TestARISupportsARI tests the SupportsARI client method
func TestARISupportsARI(t *testing.T) {
	t.Run("server supports ARI", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":    r.Host + "/new-nonce",
				"newAccount":  r.Host + "/new-account",
				"newOrder":    r.Host + "/new-order",
				"renewalInfo": r.Host + "/renewalInfo",
			})
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		supported, err := client.SupportsARI(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !supported {
			t.Error("expected server to support ARI")
		}
	})

	t.Run("server does not support ARI", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Directory without renewalInfo
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   r.Host + "/new-nonce",
				"newAccount": r.Host + "/new-account",
				"newOrder":   r.Host + "/new-order",
			})
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		supported, err := client.SupportsARI(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if supported {
			t.Error("expected server to not support ARI")
		}
	})
}

// TestARICreateOrderWithReplaces tests the CreateOrderWithReplaces method
func TestARICreateOrderWithReplaces(t *testing.T) {
	t.Run("empty domains", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		_, err := client.CreateOrderWithReplaces(context.Background(), []string{}, "YWJj.MTIz")
		if err == nil {
			t.Error("expected error for empty domains")
		}
	})

	t.Run("empty replaces certificate ID", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		_, err := client.CreateOrderWithReplaces(context.Background(), []string{"example.com"}, "")
		if err == nil {
			t.Error("expected error for empty replaces certificate ID")
		}
	})

	t.Run("server does not support ARI", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Directory without renewalInfo
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   r.Host + "/new-nonce",
				"newAccount": r.Host + "/new-account",
				"newOrder":   r.Host + "/new-order",
			})
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		_, err := client.CreateOrderWithReplaces(context.Background(), []string{"example.com"}, "YWJj.MTIz")
		if err == nil {
			t.Error("expected error when server does not support ARI")
		}
	})
}

// Helper functions

func createTestCertificateWithAKI(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345678),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Set the AuthorityKeyId to simulate an AKI extension
		AuthorityKeyId: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func createTestCertificateWithoutAKI(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345678),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// No AuthorityKeyId set
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func createTestARIClient(t *testing.T, directoryURL, renewalInfoURL string) *Client {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a mock storage
	storage := &mockARIAccountDAO{}

	client, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: key,
		Config: &Config{
			DirectoryURL:   directoryURL,
			Timeout:        30 * time.Second,
			SystemCertPool: true,
		},
		Storage: storage,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Override the HTTP client for testing to handle the renewalInfo URL
	client.httpClient = &http.Client{
		Transport: &mockARITransport{
			directoryURL:   directoryURL,
			renewalInfoURL: renewalInfoURL,
		},
		Timeout: 30 * time.Second,
	}

	return client
}

func createTestARIClientSimple(t *testing.T, serverURL string) *Client {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	storage := &mockARIAccountDAO{}

	client, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: key,
		Config: &Config{
			DirectoryURL:   serverURL,
			Timeout:        30 * time.Second,
			SystemCertPool: true,
		},
		Storage: storage,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	return client
}

// mockARITransport is a custom HTTP transport for testing ARI functionality
type mockARITransport struct {
	directoryURL   string
	renewalInfoURL string
}

func (tr *mockARITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// For the directory request, return a directory with renewalInfo
	if req.URL.String() == tr.directoryURL {
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(recorder).Encode(map[string]string{
			"newNonce":    "http://localhost/new-nonce",
			"newAccount":  "http://localhost/new-account",
			"newOrder":    "http://localhost/new-order",
			"renewalInfo": tr.renewalInfoURL,
		})
		return recorder.Result(), nil
	}

	// For other requests, use the default transport
	return http.DefaultTransport.RoundTrip(req)
}

// mockARIAccountDAO implements GenericDAO[*entities.ACMEAccount] for testing
type mockARIAccountDAO struct{}

func (m *mockARIAccountDAO) Save(_ context.Context, _ *entities.ACMEAccount) error {
	return nil
}

func (m *mockARIAccountDAO) SaveWithCondition(_ context.Context, _ *entities.ACMEAccount, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (m *mockARIAccountDAO) SaveIfAbsent(_ context.Context, _ *entities.ACMEAccount) (bool, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) Get(_ context.Context, _ uint64) (*entities.ACMEAccount, error) {
	return nil, nil
}

func (m *mockARIAccountDAO) Delete(_ context.Context, _ *entities.ACMEAccount) error {
	return nil
}

func (m *mockARIAccountDAO) Count(_ context.Context) (int, error) {
	return 0, nil
}

func (m *mockARIAccountDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAccount], error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) ForEachPage(_ context.Context, _ qrdbsdk.PageQuery, _ qrdbsdk.PagerFunc[*entities.ACMEAccount]) error {
	panic("not implemented")
}

func (m *mockARIAccountDAO) EntityType() string {
	return "accounts"
}

func (m *mockARIAccountDAO) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) QueryOneByIndex(_ context.Context, _ string, _ interface{}) (*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ACMEAccount, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMEAccount], error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockARIAccountDAO) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.ACMEAccount] {
	panic("not implemented")
}

// TestComputeRenewalTime tests the standalone ComputeRenewalTime function
func TestComputeRenewalTime(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		renewAt := ComputeRenewalTime(nil, 0.3)
		if !renewAt.IsZero() {
			t.Error("expected zero time for nil certificate")
		}
	})

	t.Run("valid certificate with 30% threshold", func(t *testing.T) {
		// Create a certificate valid for 100 days
		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt := ComputeRenewalTime(cert, 0.3)

		// With 30% threshold, should renew when 30 days remain (70 days into validity)
		expectedRenewal := notAfter.Add(-30 * 24 * time.Hour)

		// Allow 1 second tolerance for timing
		diff := renewAt.Sub(expectedRenewal)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("expected renewal around %v, got %v (diff: %v)", expectedRenewal, renewAt, diff)
		}
	})

	t.Run("zero threshold uses default 0.3", func(t *testing.T) {
		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt := ComputeRenewalTime(cert, 0)
		renewAtDefault := ComputeRenewalTime(cert, 0.3)

		diff := renewAt.Sub(renewAtDefault)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("zero threshold should use default 0.3: got %v vs %v", renewAt, renewAtDefault)
		}
	})

	t.Run("negative threshold uses default 0.3", func(t *testing.T) {
		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt := ComputeRenewalTime(cert, -0.5)
		renewAtDefault := ComputeRenewalTime(cert, 0.3)

		diff := renewAt.Sub(renewAtDefault)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("negative threshold should use default 0.3")
		}
	})

	t.Run("threshold >= 1 uses default 0.3", func(t *testing.T) {
		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt := ComputeRenewalTime(cert, 1.0)
		renewAtDefault := ComputeRenewalTime(cert, 0.3)

		diff := renewAt.Sub(renewAtDefault)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("threshold >= 1 should use default 0.3")
		}
	})

	t.Run("50% threshold", func(t *testing.T) {
		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt := ComputeRenewalTime(cert, 0.5)

		// With 50% threshold, should renew at halfway point
		expectedRenewal := notAfter.Add(-50 * 24 * time.Hour)

		diff := renewAt.Sub(expectedRenewal)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("expected renewal around %v, got %v", expectedRenewal, renewAt)
		}
	})
}

// TestNeedsRenewal tests the NeedsRenewal function
func TestNeedsRenewal(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if NeedsRenewal(nil, 0.3) {
			t.Error("nil certificate should not need renewal")
		}
	})

	t.Run("certificate needs renewal - past threshold", func(t *testing.T) {
		// Create a certificate that's 80% through its validity
		notBefore := time.Now().Add(-80 * 24 * time.Hour)
		notAfter := time.Now().Add(20 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		// With 30% threshold, should need renewal (only 20% validity remaining)
		if !NeedsRenewal(cert, 0.3) {
			t.Error("certificate should need renewal when past threshold")
		}
	})

	t.Run("certificate does not need renewal - before threshold", func(t *testing.T) {
		// Create a certificate that's 50% through its validity
		notBefore := time.Now().Add(-50 * 24 * time.Hour)
		notAfter := time.Now().Add(50 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		// With 30% threshold, should not need renewal (50% validity remaining)
		if NeedsRenewal(cert, 0.3) {
			t.Error("certificate should not need renewal when before threshold")
		}
	})

	t.Run("expired certificate needs renewal", func(t *testing.T) {
		notBefore := time.Now().Add(-100 * 24 * time.Hour)
		notAfter := time.Now().Add(-10 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		if !NeedsRenewal(cert, 0.3) {
			t.Error("expired certificate should need renewal")
		}
	})
}

// TestDaysUntilExpiry tests the DaysUntilExpiry function
func TestDaysUntilExpiry(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		days := DaysUntilExpiry(nil)
		if days != 0 {
			t.Errorf("expected 0 days for nil certificate, got %d", days)
		}
	})

	t.Run("certificate expiring in 30 days", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(30 * 24 * time.Hour),
		}

		days := DaysUntilExpiry(cert)
		// Allow for some variance due to timing
		if days < 29 || days > 31 {
			t.Errorf("expected ~30 days, got %d", days)
		}
	})

	t.Run("certificate expiring in 1 day", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(24 * time.Hour),
		}

		days := DaysUntilExpiry(cert)
		if days < 0 || days > 2 {
			t.Errorf("expected ~1 day, got %d", days)
		}
	})

	t.Run("already expired certificate", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(-24 * time.Hour),
		}

		days := DaysUntilExpiry(cert)
		if days != 0 {
			t.Errorf("expected 0 days for expired certificate, got %d", days)
		}
	})

	t.Run("certificate expiring in 365 days", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(365 * 24 * time.Hour),
		}

		days := DaysUntilExpiry(cert)
		if days < 364 || days > 366 {
			t.Errorf("expected ~365 days, got %d", days)
		}
	})
}

// TestIsExpired tests the IsExpired function
func TestIsExpired(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if !IsExpired(nil) {
			t.Error("nil certificate should be considered expired")
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(-24 * time.Hour),
		}

		if !IsExpired(cert) {
			t.Error("certificate in the past should be expired")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(24 * time.Hour),
		}

		if IsExpired(cert) {
			t.Error("certificate in the future should not be expired")
		}
	})

	t.Run("certificate expiring right now", func(t *testing.T) {
		cert := &x509.Certificate{
			NotAfter: time.Now().Add(time.Millisecond),
		}

		// Should not be expired yet (very close to now)
		if IsExpired(cert) {
			t.Error("certificate expiring in the near future should not be expired yet")
		}
	})
}

// TestIsNotYetValid tests the IsNotYetValid function
func TestIsNotYetValid(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if !IsNotYetValid(nil) {
			t.Error("nil certificate should be considered not yet valid")
		}
	})

	t.Run("not yet valid certificate", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: time.Now().Add(24 * time.Hour),
		}

		if !IsNotYetValid(cert) {
			t.Error("certificate starting in future should not be valid yet")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: time.Now().Add(-24 * time.Hour),
		}

		if IsNotYetValid(cert) {
			t.Error("certificate starting in past should be valid")
		}
	})

	t.Run("certificate becoming valid right now", func(t *testing.T) {
		cert := &x509.Certificate{
			NotBefore: time.Now().Add(-time.Millisecond),
		}

		// Should be valid now
		if IsNotYetValid(cert) {
			t.Error("certificate starting just before now should be valid")
		}
	})
}

// TestShouldRenewAt tests the Client.ShouldRenewAt method
func TestShouldRenewAt(t *testing.T) {
	t.Run("nil certificate returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{})
		}))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		_, err := client.ShouldRenewAt(context.Background(), nil, 0.3)
		if err != ErrInvalidCertificate {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("falls back to certificate-based calculation when ARI unavailable", func(t *testing.T) {
		// Create a server that doesn't support ARI
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Directory without renewalInfo
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   r.Host + "/new-nonce",
				"newAccount": r.Host + "/new-account",
				"newOrder":   r.Host + "/new-order",
			})
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		// Create a certificate valid for 100 days
		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt, err := client.ShouldRenewAt(context.Background(), cert, 0.3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should fall back to certificate-based calculation
		expectedRenewal := ComputeRenewalTime(cert, 0.3)
		diff := renewAt.Sub(expectedRenewal)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("expected renewal around %v, got %v", expectedRenewal, renewAt)
		}
	})

	t.Run("default threshold when zero provided", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{})
		}

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		client := createTestARIClientSimple(t, server.URL)

		notBefore := time.Now()
		notAfter := notBefore.Add(100 * 24 * time.Hour)

		cert := &x509.Certificate{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		}

		renewAt, err := client.ShouldRenewAt(context.Background(), cert, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should use default 0.3 threshold
		expectedRenewal := ComputeRenewalTime(cert, 0.3)
		diff := renewAt.Sub(expectedRenewal)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("expected renewal around %v, got %v", expectedRenewal, renewAt)
		}
	})
}
