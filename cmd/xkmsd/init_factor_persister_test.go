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

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// selfSignedPIVCertPEM builds a throwaway self-signed certificate PEM, the
// same shape pkg/factor/piv's Enroll produces as AuthFactorEnrollment.PublicKey.
func selfSignedPIVCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "PIV 9a"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// =============================================================================
// enrollmentToAuthFactor
// =============================================================================

func TestEnrollmentToAuthFactor_MTLS(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "mtls",
		PublicKey:  []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"),
		Metadata: map[string]string{
			"cert_spki_thumbprint": "Gv95O4SwnK8YMu5P4h2mpwuo7EDE164njOOxC2DqyZQ",
			"cert_cn":              "administrator",
		},
	}

	req, err := enrollmentToAuthFactor(42, qrdbsdk.FactorMTLS, enrollment)
	if err != nil {
		t.Fatalf("enrollmentToAuthFactor: %v", err)
	}
	if req.UserID != 42 {
		t.Errorf("UserID: want 42, got %d", req.UserID)
	}
	if req.Type != "mtls" {
		t.Errorf("Type: want mtls, got %s", req.Type)
	}
	if string(req.Credential) != "Gv95O4SwnK8YMu5P4h2mpwuo7EDE164njOOxC2DqyZQ" {
		t.Errorf("Credential: want the SPKI thumbprint bytes, got %q", req.Credential)
	}
	if req.CreatedBy != qrdbsdk.FactorCreatedByAdmin {
		t.Errorf("CreatedBy: want %s, got %s", qrdbsdk.FactorCreatedByAdmin, req.CreatedBy)
	}
}

func TestEnrollmentToAuthFactor_MTLS_MissingThumbprint(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "mtls",
		PublicKey:  []byte("cert-pem"),
		Metadata:   map[string]string{},
	}

	_, err := enrollmentToAuthFactor(1, qrdbsdk.FactorMTLS, enrollment)
	var convErr *FactorConversionError
	if !errors.As(err, &convErr) {
		t.Fatalf("expected *FactorConversionError, got %T: %v", err, err)
	}
}

func TestEnrollmentToAuthFactor_PIV(t *testing.T) {
	certPEM := selfSignedPIVCertPEM(t)
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "piv",
		PublicKey:  certPEM,
		Metadata:   map[string]string{"slot": "9a", "algorithm": "ecdsap256"},
	}

	req, err := enrollmentToAuthFactor(7, qrdbsdk.FactorPIV, enrollment)
	if err != nil {
		t.Fatalf("enrollmentToAuthFactor: %v", err)
	}
	if req.Type != "piv" {
		t.Errorf("Type: want piv, got %s", req.Type)
	}
	if len(req.Credential) != 32 {
		t.Errorf("Credential: want 32-byte SHA-256 digest, got %d bytes", len(req.Credential))
	}
	if len(req.SPKICredential) != 32 {
		t.Errorf("SPKICredential: want 32-byte SHA-256 digest, got %d bytes", len(req.SPKICredential))
	}

	// Re-derive independently and confirm the conversion used the SAME
	// canonical algorithms rather than inventing its own.
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	wantCredential := qrdbsdk.CredentialKey(cert.Raw)
	if string(req.Credential) != string(wantCredential) {
		t.Errorf("Credential mismatch: want %x, got %x", wantCredential, req.Credential)
	}
	wantSPKI, err := base64.RawURLEncoding.DecodeString(qrdbsdk.ComputeSPKIThumbprint(cert))
	if err != nil {
		t.Fatalf("decode SPKI thumbprint: %v", err)
	}
	if string(req.SPKICredential) != string(wantSPKI) {
		t.Errorf("SPKICredential mismatch: want %x, got %x", wantSPKI, req.SPKICredential)
	}
}

func TestEnrollmentToAuthFactor_PIV_InvalidCertificate(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "piv",
		PublicKey:  []byte("not a PEM certificate"),
	}

	_, err := enrollmentToAuthFactor(1, qrdbsdk.FactorPIV, enrollment)
	var convErr *FactorConversionError
	if !errors.As(err, &convErr) {
		t.Fatalf("expected *FactorConversionError, got %T: %v", err, err)
	}
}

func TestEnrollmentToAuthFactor_FIDO2(t *testing.T) {
	credentialID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "fido2",
		PublicKey:  []byte("cose-public-key"),
		Metadata: map[string]string{
			"credential_id": base64.RawURLEncoding.EncodeToString(credentialID),
			"rp_id":         "xkms.example.com",
		},
	}

	req, err := enrollmentToAuthFactor(3, qrdbsdk.FactorFIDO2, enrollment)
	if err != nil {
		t.Fatalf("enrollmentToAuthFactor: %v", err)
	}
	if req.Type != "fido2" {
		t.Errorf("Type: want fido2, got %s", req.Type)
	}
	if string(req.Credential) != string(credentialID) {
		t.Errorf("Credential: want raw credential ID %x, got %x", credentialID, req.Credential)
	}
	if len(req.SPKICredential) != 0 {
		t.Errorf("SPKICredential: want empty for fido2, got %x", req.SPKICredential)
	}
}

func TestEnrollmentToAuthFactor_FIDO2_MissingCredentialID(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "fido2",
		PublicKey:  []byte("cose-public-key"),
		Metadata:   map[string]string{},
	}

	_, err := enrollmentToAuthFactor(1, qrdbsdk.FactorFIDO2, enrollment)
	var convErr *FactorConversionError
	if !errors.As(err, &convErr) {
		t.Fatalf("expected *FactorConversionError, got %T: %v", err, err)
	}
}

func TestEnrollmentToAuthFactor_NilEnrollment(t *testing.T) {
	_, err := enrollmentToAuthFactor(1, qrdbsdk.FactorMTLS, nil)
	var convErr *FactorConversionError
	if !errors.As(err, &convErr) {
		t.Fatalf("expected *FactorConversionError, got %T: %v", err, err)
	}
}

func TestEnrollmentToAuthFactor_UnsupportedFactor(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{FactorName: "pkcs11"}
	_, err := enrollmentToAuthFactor(1, qrdbsdk.AdminFactor("pkcs11"), enrollment)
	var unsupportedErr *UnsupportedPersistFactorError
	if !errors.As(err, &unsupportedErr) {
		t.Fatalf("expected *UnsupportedPersistFactorError, got %T: %v", err, err)
	}
}

// =============================================================================
// nodeFactorPersister
// =============================================================================

// fakeUserAuthFactorClient is a minimal qrdbtransport.UserAuthFactorClient
// double that records every AddAuthFactor call and can be configured to fail
// on a chosen call index. The other methods are never exercised by
// nodeFactorPersister and panic if called, so an accidental new dependency on
// them fails loudly instead of silently returning a zero value.
type fakeUserAuthFactorClient struct {
	adds      []*qrdbtransport.AuthFactorAddRequest
	failOnAdd int // 1-indexed call to fail on; 0 means never fail
}

var _ qrdbtransport.UserAuthFactorClient = (*fakeUserAuthFactorClient)(nil)

func (f *fakeUserAuthFactorClient) AddAuthFactor(_ context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	f.adds = append(f.adds, req)
	if f.failOnAdd != 0 && len(f.adds) == f.failOnAdd {
		return nil, errors.New("simulated store failure")
	}
	return &qrdbtransport.AuthFactorAddResponse{}, nil
}

func (f *fakeUserAuthFactorClient) ListAuthFactors(context.Context, *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error) {
	panic("not implemented")
}
func (f *fakeUserAuthFactorClient) GetAuthFactor(context.Context, *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error) {
	panic("not implemented")
}
func (f *fakeUserAuthFactorClient) RemoveAuthFactor(context.Context, *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	panic("not implemented")
}
func (f *fakeUserAuthFactorClient) RotateAuthFactor(context.Context, *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	panic("not implemented")
}
func (f *fakeUserAuthFactorClient) RelabelAuthFactor(context.Context, *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error) {
	panic("not implemented")
}
func (f *fakeUserAuthFactorClient) LoginAuthFactor(context.Context, *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error) {
	panic("not implemented")
}

func TestNodeFactorPersister_PersistAdminFactor_Success(t *testing.T) {
	client := &fakeUserAuthFactorClient{}
	p := &nodeFactorPersister{client: client, userID: 9}

	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "mtls",
		Metadata:   map[string]string{"cert_spki_thumbprint": "thumb"},
	}
	if err := p.PersistAdminFactor(context.Background(), qrdbsdk.FactorMTLS, enrollment); err != nil {
		t.Fatalf("PersistAdminFactor: %v", err)
	}
	if len(client.adds) != 1 {
		t.Fatalf("expected 1 AddAuthFactor call, got %d", len(client.adds))
	}
	if client.adds[0].UserID != 9 {
		t.Errorf("UserID: want 9, got %d", client.adds[0].UserID)
	}
}

// TestNodeFactorPersister_FailsClosed_EarlierFactorsStayPersisted verifies
// the contract qrdbsdk.EnrollAdminFactors depends on: PersistAdminFactor is
// called once per factor as it enrolls, so a failure on a LATER factor must
// not undo or block the write already made for an EARLIER one, and the
// failure itself must be a typed error a caller can classify with errors.As.
func TestNodeFactorPersister_FailsClosed_EarlierFactorsStayPersisted(t *testing.T) {
	client := &fakeUserAuthFactorClient{failOnAdd: 2}
	p := &nodeFactorPersister{client: client, userID: 1}
	ctx := context.Background()

	mtls := &qrdbsdk.AuthFactorEnrollment{FactorName: "mtls", Metadata: map[string]string{"cert_spki_thumbprint": "thumb-a"}}
	if err := p.PersistAdminFactor(ctx, qrdbsdk.FactorMTLS, mtls); err != nil {
		t.Fatalf("first PersistAdminFactor: %v", err)
	}

	fido2 := &qrdbsdk.AuthFactorEnrollment{FactorName: "fido2", Metadata: map[string]string{"credential_id": base64.RawURLEncoding.EncodeToString([]byte("cred"))}}
	err := p.PersistAdminFactor(ctx, qrdbsdk.FactorFIDO2, fido2)
	if err == nil {
		t.Fatal("expected the second PersistAdminFactor to fail")
	}
	var wrapped *WrappedDetailError
	if !errors.As(err, &wrapped) || !errors.Is(err, ErrFactorPersistFailed) {
		t.Fatalf("expected a WrappedDetailError wrapping ErrFactorPersistFailed, got %T: %v", err, err)
	}
	if wrapped.Detail != "fido2" {
		t.Errorf("Detail: want fido2, got %q", wrapped.Detail)
	}

	// The first (successful) call must still be recorded: a later failure
	// does not roll it back.
	if len(client.adds) != 2 {
		t.Fatalf("expected 2 AddAuthFactor calls (one persisted, one attempted), got %d", len(client.adds))
	}
	if client.adds[0].Type != "mtls" {
		t.Errorf("first persisted factor: want mtls, got %s", client.adds[0].Type)
	}
}

func TestNodeFactorPersister_ConversionFailure_NeverReachesStore(t *testing.T) {
	client := &fakeUserAuthFactorClient{}
	p := &nodeFactorPersister{client: client, userID: 1}

	// mtls enrollment missing the thumbprint metadata fails conversion
	// before any store call is attempted.
	err := p.PersistAdminFactor(context.Background(), qrdbsdk.FactorMTLS, &qrdbsdk.AuthFactorEnrollment{FactorName: "mtls"})
	var convErr *FactorConversionError
	if !errors.As(err, &convErr) {
		t.Fatalf("expected *FactorConversionError, got %T: %v", err, err)
	}
	if len(client.adds) != 0 {
		t.Errorf("expected no AddAuthFactor call on conversion failure, got %d", len(client.adds))
	}
}
