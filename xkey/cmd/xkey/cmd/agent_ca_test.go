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

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// caTestFixture is a real, self-signed certificate authority used to give
// the fake xkmsd endpoint genuine certificate material to return.
type caTestFixture struct {
	certPEM []byte
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
}

// newCATestFixture mints a real CA certificate in memory.
func newCATestFixture(t *testing.T) *caTestFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkey agent test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	return &caTestFixture{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		cert:    cert,
	}
}

// issue signs a leaf certificate for the given common name, producing real
// PEM material for the fake endpoint's sign-csr response.
func (f *caTestFixture) issue(t *testing.T, commonName string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.cert, &key.PublicKey, f.key)
	if err != nil {
		t.Fatalf("sign leaf certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakeXKMSd is an HTTP endpoint speaking the documented xkmsd REST wire
// contract for the CA verbs the agent enrollment path uses. The server half
// of the contract is covered by go-xkms's own handler tests; this exercises
// the CLI's client half against real certificate material.
type fakeXKMSd struct {
	server *httptest.Server

	// caPEM is returned by GET /api/v1/ca/certificate.
	caPEM []byte

	// signResponse is returned by POST /api/v1/ca/sign-csr.
	signResponse transport.SignCSRResponse

	// signStatus, when >= 400, makes sign-csr fail with an error document.
	signStatus int

	// revokeResponse is returned by POST /api/v1/ca/revoke.
	revokeResponse transport.RevokeCertificateResponse

	// isRevokedResponse is returned by GET /api/v1/ca/revoked/{serial}.
	isRevokedResponse transport.IsRevokedResponse

	// isRevokedStatus, when >= 400, makes the revocation check fail with
	// an error document.
	isRevokedStatus int

	// lastSignRequest records the most recent sign-csr request body.
	lastSignRequest transport.SignCSRRequest

	// lastRevokeRequest records the most recent revoke request body.
	lastRevokeRequest transport.RevokeCertificateRequest

	// lastIsRevokedSerial records the most recent is-revoked request's
	// serial number.
	lastIsRevokedSerial string
}

// newFakeXKMSd starts a fake xkmsd endpoint serving the CA verbs.
func newFakeXKMSd(t *testing.T, ca *caTestFixture) *fakeXKMSd {
	t.Helper()

	fake := &fakeXKMSd{caPEM: ca.certPEM}
	fake.signResponse = transport.SignCSRResponse{
		CertificatePEM: ca.issue(t, "agent-under-test"),
		ChainPEM:       ca.certPEM,
		SerialNumber:   "0A0B0C",
	}
	fake.revokeResponse = transport.RevokeCertificateResponse{Success: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, http.StatusOK, transport.HealthResponse{Status: "ok", Version: "test"})
	})
	mux.HandleFunc("/api/v1/ca/certificate", func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(t, w, http.StatusOK, transport.GetCACertificateResponse{
			CertificatePEM: fake.caPEM,
			Subject:        "CN=xkey agent test CA",
			Issuer:         "CN=xkey agent test CA",
			SerialNumber:   "01",
			IsCA:           true,
		})
	})
	mux.HandleFunc("/api/v1/ca/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&fake.lastSignRequest); err != nil {
			t.Errorf("decode sign-csr request: %v", err)
		}
		if fake.signStatus >= 400 {
			writeTestJSON(t, w, fake.signStatus, map[string]string{
				"error":   "sign_denied",
				"message": "profile not permitted",
			})
			return
		}
		writeTestJSON(t, w, http.StatusOK, fake.signResponse)
	})
	mux.HandleFunc("/api/v1/ca/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&fake.lastRevokeRequest); err != nil {
			t.Errorf("decode revoke request: %v", err)
		}
		writeTestJSON(t, w, http.StatusOK, fake.revokeResponse)
	})
	mux.HandleFunc("GET /api/v1/ca/revoked/{serial}", func(w http.ResponseWriter, r *http.Request) {
		fake.lastIsRevokedSerial = r.PathValue("serial")
		if fake.isRevokedStatus >= 400 {
			writeTestJSON(t, w, fake.isRevokedStatus, map[string]string{
				"error":   "is_revoked_failed",
				"message": "unable to determine revocation status",
			})
			return
		}
		writeTestJSON(t, w, http.StatusOK, fake.isRevokedResponse)
	})

	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

// writeTestJSON encodes a JSON response body for the fake endpoint.
func writeTestJSON(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// useTestXKMSdEndpoint neutralizes every endpoint source and points the
// CLI at url. An empty url means "no certificate authority configured".
func useTestXKMSdEndpoint(t *testing.T, url string) {
	t.Helper()

	isolateXKMSdEndpoint(t)
	xkmsdURL = url
}

// connectTestCA builds an xkmsdCA against the fake endpoint.
func connectTestCA(t *testing.T, fake *fakeXKMSd) *xkmsdCA {
	t.Helper()

	useTestXKMSdEndpoint(t, fake.server.URL)

	ca, err := newAgentCA(agentCertProfileDefault, 30)
	if err != nil {
		t.Fatalf("newAgentCA: %v", err)
	}
	t.Cleanup(func() {
		if err := ca.Close(); err != nil {
			t.Errorf("close CA client: %v", err)
		}
	})
	return ca
}

func TestNewAgentCA_NoAuthorityConfigured(t *testing.T) {
	useTestXKMSdEndpoint(t, "")

	ca, err := newAgentCA(agentCertProfileDefault, 0)
	if !errors.Is(err, ErrAgentCAUnavailable) {
		t.Fatalf("newAgentCA = %v, want ErrAgentCAUnavailable", err)
	}
	if ca != nil {
		t.Error("newAgentCA returned a CA despite failing closed")
	}
	if !errors.Is(err, ErrXKMSdURLRequired) {
		t.Errorf("error does not explain the missing server URL: %v", err)
	}
}

func TestNewAgentCA_UnreachableAuthority(t *testing.T) {
	// Port 9 (discard) refuses connections, so the transport handshake fails.
	useTestXKMSdEndpoint(t, "http://127.0.0.1:9")

	if _, err := newAgentCA(agentCertProfileDefault, 0); !errors.Is(err, ErrAgentCAUnavailable) {
		t.Fatalf("newAgentCA = %v, want ErrAgentCAUnavailable", err)
	}
}

func TestNewAgentCA_AuthorityWithoutCertificate(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	fake.caPEM = nil
	useTestXKMSdEndpoint(t, fake.server.URL)

	if _, err := newAgentCA(agentCertProfileDefault, 0); !errors.Is(err, ErrAgentCAUnavailable) {
		t.Fatalf("newAgentCA = %v, want ErrAgentCAUnavailable", err)
	}
}

func TestXKMSdCA_GetCACertificate(t *testing.T) {
	fixture := newCATestFixture(t)
	fake := newFakeXKMSd(t, fixture)
	ca := connectTestCA(t, fake)

	caPEM, err := ca.GetCACertificate()
	if err != nil {
		t.Fatalf("GetCACertificate: %v", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatalf("CA certificate is not PEM: %q", caPEM)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	if !parsed.IsCA {
		t.Error("returned certificate is not a CA certificate")
	}
	if parsed.Subject.CommonName != "xkey agent test CA" {
		t.Errorf("CA common name = %q, want %q", parsed.Subject.CommonName, "xkey agent test CA")
	}
}

func TestXKMSdCA_GetCACertificate_EmptyResponse(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.caPEM = nil
	if _, err := ca.GetCACertificate(); !errors.Is(err, ErrAgentCAEmptyResponse) {
		t.Fatalf("GetCACertificate = %v, want ErrAgentCAEmptyResponse", err)
	}
}

func TestXKMSdCA_SignCSR(t *testing.T) {
	fixture := newCATestFixture(t)
	fake := newFakeXKMSd(t, fixture)
	ca := connectTestCA(t, fake)

	csrPEM := []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n")
	certPEM, err := ca.SignCSR(csrPEM)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	// The issued certificate must verify against the authority that
	// answered, proving no synthetic material is handed to agents.
	block, rest := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("issued certificate is not PEM: %q", certPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if err := leaf.CheckSignatureFrom(fixture.cert); err != nil {
		t.Errorf("issued certificate is not signed by the CA: %v", err)
	}
	if len(rest) == 0 {
		t.Error("issuer chain was not appended to the issued certificate")
	}

	if string(fake.lastSignRequest.CSRPEM) != string(csrPEM) {
		t.Errorf("CSR forwarded to the CA = %q, want %q", fake.lastSignRequest.CSRPEM, csrPEM)
	}
	if fake.lastSignRequest.Profile != agentCertProfileDefault {
		t.Errorf("profile = %q, want %q", fake.lastSignRequest.Profile, agentCertProfileDefault)
	}
	if fake.lastSignRequest.ValidityDays != 30 {
		t.Errorf("validity days = %d, want 30", fake.lastSignRequest.ValidityDays)
	}
}

func TestXKMSdCA_SignCSR_AuthorityRejects(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.signStatus = http.StatusForbidden
	if _, err := ca.SignCSR([]byte("csr")); !errors.Is(err, ErrAgentCASignFailed) {
		t.Fatalf("SignCSR = %v, want ErrAgentCASignFailed", err)
	}
}

func TestXKMSdCA_SignCSR_EmptyCertificate(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.signResponse = transport.SignCSRResponse{SerialNumber: "01"}
	if _, err := ca.SignCSR([]byte("csr")); !errors.Is(err, ErrAgentCAEmptyResponse) {
		t.Fatalf("SignCSR = %v, want ErrAgentCAEmptyResponse", err)
	}
}

func TestXKMSdCA_RevokeCertificate(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	if err := ca.RevokeCertificate("0A0B0C"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if fake.lastRevokeRequest.SerialNumber != "0A0B0C" {
		t.Errorf("serial = %q, want 0A0B0C", fake.lastRevokeRequest.SerialNumber)
	}
	if fake.lastRevokeRequest.Reason != agentRevocationReason {
		t.Errorf("reason = %d, want %d", fake.lastRevokeRequest.Reason, agentRevocationReason)
	}
}

func TestXKMSdCA_RevokeCertificate_AuthorityRefuses(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.revokeResponse = transport.RevokeCertificateResponse{
		Success: false,
		Message: "unknown serial number",
	}
	err := ca.RevokeCertificate("DEADBEEF")
	if !errors.Is(err, ErrAgentCARevokeFailed) {
		t.Fatalf("RevokeCertificate = %v, want ErrAgentCARevokeFailed", err)
	}
	if !strings.Contains(err.Error(), "unknown serial number") {
		t.Errorf("error does not carry the CA message: %v", err)
	}
}

func TestXKMSdCA_IsRevoked_NotRevoked(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.isRevokedResponse = transport.IsRevokedResponse{Revoked: false}
	revoked, err := ca.IsRevoked("0A0B0C")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("IsRevoked = true, want false")
	}
	if fake.lastIsRevokedSerial != "0A0B0C" {
		t.Errorf("serial sent = %q, want 0A0B0C", fake.lastIsRevokedSerial)
	}
}

func TestXKMSdCA_IsRevoked_Revoked(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.isRevokedResponse = transport.IsRevokedResponse{Revoked: true, Reason: agentRevocationReason}
	revoked, err := ca.IsRevoked("DEADBEEF")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("IsRevoked = false, want true")
	}
}

func TestXKMSdCA_IsRevoked_AuthorityFailure(t *testing.T) {
	fake := newFakeXKMSd(t, newCATestFixture(t))
	ca := connectTestCA(t, fake)

	fake.isRevokedStatus = http.StatusInternalServerError
	if _, err := ca.IsRevoked("0A0B0C"); !errors.Is(err, ErrAgentCARevocationCheckFailed) {
		t.Fatalf("IsRevoked = %v, want ErrAgentCARevocationCheckFailed", err)
	}
}

func TestAgentCertProfile(t *testing.T) {
	if got := agentCertProfile(agentStartCmd); got != agentCertProfileDefault {
		t.Errorf("agentCertProfile default = %q, want %q", got, agentCertProfileDefault)
	}

	if err := setFlagForTest(t, agentStartCmd.Flags(), "cert-profile", "idevid"); err != nil {
		t.Fatalf("set cert-profile: %v", err)
	}
	t.Cleanup(func() {
		if err := setFlagForTest(t, agentStartCmd.Flags(), "cert-profile", agentCertProfileDefault); err != nil {
			t.Errorf("restore cert-profile: %v", err)
		}
	})
	if got := agentCertProfile(agentStartCmd); got != "idevid" {
		t.Errorf("agentCertProfile = %q, want idevid", got)
	}
}

// TestNoPlaceholderCertificateAuthority guards against reintroducing a
// signer that fabricates certificate material. The agent server must only
// ever hand out certificates issued by a real certificate authority.
func TestNoPlaceholderCertificateAuthority(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	forbidden := []string{"placeholderCA", "placeholder-ca"}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, token := range forbidden {
			if strings.Contains(string(source), token) {
				t.Errorf("%s reintroduces a placeholder certificate authority (%q)", name, token)
			}
		}
	}
}
