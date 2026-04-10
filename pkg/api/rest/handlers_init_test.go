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

package rest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockCA for init handler tests (mirrors pkg/init/ceremony_test.go).
// ---------------------------------------------------------------------------

type initTestMockCA struct {
	cert       *x509.Certificate
	certPEM    []byte
	privateKey *ecdsa.PrivateKey
}

var _ ca.XKMSCA = (*initTestMockCA)(nil)

func newInitTestMockCA(t *testing.T) *initTestMockCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &initTestMockCA{cert: cert, certPEM: certPEM, privateKey: key}
}

func (m *initTestMockCA) Public() crypto.PublicKey { return &m.privateKey.PublicKey }

func (m *initTestMockCA) Sign(r io.Reader, d []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(r, m.privateKey, d)
}

func (m *initTestMockCA) Init() error         { return nil }
func (m *initTestMockCA) Load() error         { return nil }
func (m *initTestMockCA) IsInitialized() bool { return true }
func (m *initTestMockCA) Identity() string    { return m.cert.Subject.CommonName }
func (m *initTestMockCA) Config() *ca.Identity {
	return &ca.Identity{Subject: ca.Subject{CommonName: m.cert.Subject.CommonName}}
}
func (m *initTestMockCA) KeyStore() xkms.Backend                                    { return nil }
func (m *initTestMockCA) CertStore() certstore.CertStore                            { return nil }
func (m *initTestMockCA) CACertificate() (*x509.Certificate, error)                 { return m.cert, nil }
func (m *initTestMockCA) CABundle() ([]byte, error)                                 { return m.certPEM, nil }
func (m *initTestMockCA) CreateCSR(_ *ca.CertificateRequest) ([]byte, error)        { return nil, nil }
func (m *initTestMockCA) Verify(_ *x509.Certificate) ([][]*x509.Certificate, error) { return nil, nil }
func (m *initTestMockCA) Revoke(_ *big.Int, _ int) error                            { return nil }
func (m *initTestMockCA) GenerateCRL() ([]byte, error)                              { return nil, nil }
func (m *initTestMockCA) IsRevoked(_ *big.Int) (bool, error)                        { return false, nil }
func (m *initTestMockCA) TLSCertificate(_ *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *initTestMockCA) TLSConfig(_ *types.KeyAttributes) (*tls.Config, error) { return nil, nil }

func (m *initTestMockCA) SignCSR(csrPEM []byte, _ *ca.SignOptions) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("mockCA: invalid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, csr.PublicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func (m *initTestMockCA) IssueCertificate(req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     req.KeyUsage,
		ExtKeyUsage:  req.ExtKeyUsage,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, &key.PublicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &ca.IssuedCertificate{
		Certificate:    cert,
		CertificatePEM: certPEMBytes,
		PrivateKey:     key,
		PrivateKeyPEM:  keyPEM,
	}, nil
}

func (m *initTestMockCA) IssueCertificateWithProfile(req *ca.CertificateRequest, _ string) (*ca.IssuedCertificate, error) {
	return m.IssueCertificate(req)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func initTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func initTestBarrier(t *testing.T) *seal.Barrier {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(initTestLogger(), base, seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	return barrier
}

func initTestCredService(t *testing.T) *credentials.Service {
	t.Helper()
	svc, err := credentials.New(
		&credentials.Config{Strategy: credentials.StrategyManual},
		nil, nil, initTestLogger(),
	)
	require.NoError(t, err)
	return svc
}

func initTestGenerateCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, key
}

// initTestMofNService creates an initialized M-of-N ceremony service with
// handlers, officer private keys, and the mock CA.
func initTestMofNService(t *testing.T, threshold, numOfficers int) (*InitHandlers, []*ecdsa.PrivateKey, *initTestMockCA) {
	t.Helper()

	officers := make([]initialize.OfficerConfig, numOfficers)
	keys := make([]*ecdsa.PrivateKey, numOfficers)
	for i := 0; i < numOfficers; i++ {
		csrPEM, key := initTestGenerateCSR(t, "officer-"+string(rune('A'+i)))
		officers[i] = initialize.OfficerConfig{
			Username: "officer-" + string(rune('A'+i)),
			CSRPEM:   csrPEM,
		}
		keys[i] = key
	}

	cfg := &initialize.CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Threshold:              threshold,
		Officers:               officers,
		Hostname:               "localhost",
	}

	barrier := initTestBarrier(t)
	svc, err := initialize.NewCeremonyService(cfg, barrier, initTestCredService(t), initTestLogger())
	require.NoError(t, err)

	mockCA := newInitTestMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	handlers := NewInitHandlers(svc, initTestLogger())
	return handlers, keys, mockCA
}

// initTestSingleAdminService creates an initialized single-admin ceremony service.
func initTestSingleAdminService(t *testing.T) *InitHandlers {
	t.Helper()

	cfg := &initialize.CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Hostname:               "localhost",
	}

	barrier := initTestBarrier(t)
	svc, err := initialize.NewCeremonyService(cfg, barrier, initTestCredService(t), initTestLogger())
	require.NoError(t, err)

	mockCA := newInitTestMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	return NewInitHandlers(svc, initTestLogger())
}

// initTestAwaitingService creates an uninitialized ceremony service.
func initTestAwaitingService(t *testing.T) *InitHandlers {
	t.Helper()

	cfg := &initialize.CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Hostname:               "localhost",
	}

	barrier := initTestBarrier(t)
	svc, err := initialize.NewCeremonyService(cfg, barrier, initTestCredService(t), initTestLogger())
	require.NoError(t, err)

	return NewInitHandlers(svc, initTestLogger())
}

// ---------------------------------------------------------------------------
// HandleGetStatus tests
// ---------------------------------------------------------------------------

// TestInitHandleGetStatus_AwaitingInit verifies the status endpoint returns
// awaiting_init for an uninitialized ceremony service.
func TestInitHandleGetStatus_AwaitingInit(t *testing.T) {
	handlers := initTestAwaitingService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/init/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp InitStatusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, string(initialize.StateAwaitingInit), resp.State)
}

// TestInitHandleGetStatus_Enrolling verifies the status endpoint returns
// enrolling after M-of-N initialization.
func TestInitHandleGetStatus_Enrolling(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/init/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp InitStatusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, string(initialize.StateEnrolling), resp.State)
}

// TestInitHandleGetStatus_Operational verifies the status endpoint returns
// operational after single-admin initialization.
func TestInitHandleGetStatus_Operational(t *testing.T) {
	handlers := initTestSingleAdminService(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/init/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp InitStatusResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, string(initialize.StateOperational), resp.State)
}

// ---------------------------------------------------------------------------
// HandleClaimCertBegin tests
// ---------------------------------------------------------------------------

// TestInitHandleClaimCertBegin_Success verifies that claim-cert begin returns
// a nonce and metadata for a valid officer username.
func TestInitHandleClaimCertBegin_Success(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertBeginRequest{Username: "officer-A"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertBegin(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ClaimCertBeginResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Nonce)
	assert.Equal(t, "officer-A", resp.Username)
	assert.True(t, resp.ExpiresAt.After(time.Now()))
}

// TestInitHandleClaimCertBegin_InvalidJSON verifies 400 for malformed JSON.
func TestInitHandleClaimCertBegin_InvalidJSON(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertBegin(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertBegin_MissingUsername verifies 400 for empty username.
func TestInitHandleClaimCertBegin_MissingUsername(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertBeginRequest{Username: ""})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertBegin(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertBegin_UnknownOfficer verifies 404 for a nonexistent username.
func TestInitHandleClaimCertBegin_UnknownOfficer(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertBeginRequest{Username: "nonexistent"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertBegin(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestInitHandleClaimCertBegin_NotEnrolling verifies 409 when the ceremony
// is not in the enrolling state.
func TestInitHandleClaimCertBegin_NotEnrolling(t *testing.T) {
	handlers := initTestAwaitingService(t)

	body, err := json.Marshal(ClaimCertBeginRequest{Username: "officer-A"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertBegin(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// ---------------------------------------------------------------------------
// HandleClaimCertComplete tests
// ---------------------------------------------------------------------------

// TestInitHandleClaimCertComplete_Success verifies the full claim-cert flow.
func TestInitHandleClaimCertComplete_Success(t *testing.T) {
	handlers, keys, _ := initTestMofNService(t, 2, 3)

	// Begin claim to get a nonce.
	beginBody, err := json.Marshal(ClaimCertBeginRequest{Username: "officer-A"})
	require.NoError(t, err)

	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(beginBody))
	beginReq.Header.Set("Content-Type", "application/json")
	beginRec := httptest.NewRecorder()
	handlers.HandleClaimCertBegin(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code)

	var beginResp ClaimCertBeginResponse
	err = json.NewDecoder(beginRec.Body).Decode(&beginResp)
	require.NoError(t, err)

	// Sign the nonce with the officer's private key.
	nonceBytes, err := hex.DecodeString(beginResp.Nonce)
	require.NoError(t, err)
	hash := sha256.Sum256(nonceBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Complete the claim.
	completeBody, err := json.Marshal(ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     beginResp.Nonce,
		Signature: sigB64,
	})
	require.NoError(t, err)

	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeRec := httptest.NewRecorder()
	handlers.HandleClaimCertComplete(completeRec, completeReq)

	assert.Equal(t, http.StatusOK, completeRec.Code)

	var completeResp ClaimCertCompleteResponse
	err = json.NewDecoder(completeRec.Body).Decode(&completeResp)
	require.NoError(t, err)
	assert.NotEmpty(t, completeResp.CertPEM)
	assert.NotEmpty(t, completeResp.CACertPEM)
}

// TestInitHandleClaimCertComplete_InvalidJSON verifies 400 for malformed JSON.
func TestInitHandleClaimCertComplete_InvalidJSON(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertComplete(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertComplete_MissingUsername verifies 400 for empty username.
func TestInitHandleClaimCertComplete_MissingUsername(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertCompleteRequest{
		Nonce:     "abc",
		Signature: "def",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertComplete(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertComplete_MissingNonce verifies 400 for empty nonce.
func TestInitHandleClaimCertComplete_MissingNonce(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertCompleteRequest{
		Username:  "officer-A",
		Signature: "def",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertComplete(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertComplete_MissingSignature verifies 400 for empty signature.
func TestInitHandleClaimCertComplete_MissingSignature(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertCompleteRequest{
		Username: "officer-A",
		Nonce:    "abc",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertComplete(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertComplete_InvalidBase64 verifies 400 for bad base64 signature.
func TestInitHandleClaimCertComplete_InvalidBase64(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     "abc",
		Signature: "not-valid-base64!!!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertComplete(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimCertComplete_WrongSignature verifies 401 for invalid signature.
func TestInitHandleClaimCertComplete_WrongSignature(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	// Begin claim.
	beginBody, err := json.Marshal(ClaimCertBeginRequest{Username: "officer-A"})
	require.NoError(t, err)

	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(beginBody))
	beginReq.Header.Set("Content-Type", "application/json")
	beginRec := httptest.NewRecorder()
	handlers.HandleClaimCertBegin(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code)

	var beginResp ClaimCertBeginResponse
	err = json.NewDecoder(beginRec.Body).Decode(&beginResp)
	require.NoError(t, err)

	// Sign with a wrong key.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nonceBytes, err := hex.DecodeString(beginResp.Nonce)
	require.NoError(t, err)
	hash := sha256.Sum256(nonceBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, wrongKey, hash[:])
	require.NoError(t, err)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	completeBody, err := json.Marshal(ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     beginResp.Nonce,
		Signature: sigB64,
	})
	require.NoError(t, err)

	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeRec := httptest.NewRecorder()
	handlers.HandleClaimCertComplete(completeRec, completeReq)

	assert.Equal(t, http.StatusUnauthorized, completeRec.Code)
}

// TestInitHandleClaimCertComplete_NotEnrolling verifies 409 when ceremony
// is not in the enrolling state.
func TestInitHandleClaimCertComplete_NotEnrolling(t *testing.T) {
	handlers := initTestAwaitingService(t)

	body, err := json.Marshal(ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     hex.EncodeToString(make([]byte, 32)),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimCertComplete(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// ---------------------------------------------------------------------------
// HandleClaimShare tests
// ---------------------------------------------------------------------------

// TestInitHandleClaimShare_Success verifies successful share claim.
func TestInitHandleClaimShare_Success(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimShareRequest{Username: "officer-A"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimShare(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ClaimShareResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Share)
}

// TestInitHandleClaimShare_InvalidJSON verifies 400 for malformed JSON.
func TestInitHandleClaimShare_InvalidJSON(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimShare(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimShare_MissingUsername verifies 400 for empty username.
func TestInitHandleClaimShare_MissingUsername(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimShareRequest{Username: ""})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimShare(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestInitHandleClaimShare_UnknownOfficer verifies 404 for a nonexistent username.
func TestInitHandleClaimShare_UnknownOfficer(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimShareRequest{Username: "nonexistent"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimShare(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestInitHandleClaimShare_AlreadyClaimed verifies 409 when a share has
// already been claimed.
func TestInitHandleClaimShare_AlreadyClaimed(t *testing.T) {
	handlers, _, _ := initTestMofNService(t, 2, 3)

	body, err := json.Marshal(ClaimShareRequest{Username: "officer-A"})
	require.NoError(t, err)

	// First claim succeeds.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.HandleClaimShare(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Second claim fails.
	body, err = json.Marshal(ClaimShareRequest{Username: "officer-A"})
	require.NoError(t, err)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handlers.HandleClaimShare(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// TestInitHandleClaimShare_NotEnrolling verifies 409 when ceremony is not
// in the enrolling state.
func TestInitHandleClaimShare_NotEnrolling(t *testing.T) {
	handlers := initTestAwaitingService(t)

	body, err := json.Marshal(ClaimShareRequest{Username: "officer-A"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleClaimShare(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// ---------------------------------------------------------------------------
// Constructor and error mapping tests
// ---------------------------------------------------------------------------

// TestNewInitHandlers_NilLogger verifies that NewInitHandlers uses a default
// logger when nil is passed.
func TestNewInitHandlers_NilLogger(t *testing.T) {
	cfg := &initialize.CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Hostname:               "localhost",
	}
	barrier := initTestBarrier(t)
	svc, err := initialize.NewCeremonyService(cfg, barrier, initTestCredService(t), initTestLogger())
	require.NoError(t, err)

	handlers := NewInitHandlers(svc, nil)
	assert.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
}

// TestMapInitError_UnknownError verifies that unknown errors map to 500.
func TestMapInitError_UnknownError(t *testing.T) {
	status := mapInitError(assert.AnError)
	assert.Equal(t, http.StatusInternalServerError, status)
}

// TestMapInitError_KnownCodes verifies that known init errors map to the
// correct HTTP status codes.
func TestMapInitError_KnownCodes(t *testing.T) {
	tests := []struct {
		err      error
		expected int
	}{
		{initialize.ErrNotInEnrollingState, http.StatusConflict},
		{initialize.ErrPendingCertNotFound, http.StatusNotFound},
		{initialize.ErrCertAlreadyClaimed, http.StatusConflict},
		{initialize.ErrShareNotFound, http.StatusNotFound},
		{initialize.ErrShareAlreadyClaimed, http.StatusConflict},
		{initialize.ErrChallengeVerificationFailed, http.StatusUnauthorized},
		{initialize.ErrAlreadyInitialized, http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			status := mapInitError(tt.err)
			assert.Equal(t, tt.expected, status)
		})
	}
}
