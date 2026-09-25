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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubConnectionService builds a ConnectionService whose state points at
// the given httptest.Server. It does not start a real connection.
func stubConnectionService(srv *httptest.Server) *ConnectionService {
	cs := NewConnectionService()
	cs.state.Store(&ConnectionInfo{
		State:   "connected",
		Address: strings.TrimPrefix(srv.URL, "http://"),
		TLS:     false,
	})
	return cs
}

func TestSecurityFactorService_ListFactors(t *testing.T) {
	want := ListFactorsResponse{
		Factors: []AuthFactor{
			{
				ID:           "f1",
				UserID:       "u1",
				Type:         AuthFactorTypeFIDO2,
				Label:        "YubiKey 5",
				RegisteredAt: "2026-01-01T00:00:00Z",
			},
		},
		Total: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users/u1/factors", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	got, err := svc.ListFactors("u1")
	require.NoError(t, err)
	require.Len(t, got.Factors, 1)
	assert.Equal(t, "f1", got.Factors[0].ID)
	assert.Equal(t, AuthFactorTypeFIDO2, got.Factors[0].Type)
}

func TestSecurityFactorService_ListFactors_EmptyUserID(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.ListFactors("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID required")
}

func TestSecurityFactorService_AddFactor(t *testing.T) {
	var calledPath string
	var calledBody AddFactorRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&calledBody)
		resp := AddFactorResponse{
			Factor: AuthFactor{ID: "new-f", Type: AuthFactorTypeFIDO2, Label: "YubiKey"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	got, err := svc.AddFactor("u1", AddFactorRequest{
		Type:  AuthFactorTypeFIDO2,
		Label: "YubiKey",
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/factors", calledPath)
	assert.Equal(t, AuthFactorTypeFIDO2, calledBody.Type)
	assert.Equal(t, "new-f", got.Factor.ID)
}

func TestSecurityFactorService_AddFactor_InvalidType(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.AddFactor("u1", AddFactorRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidFactorType)
}

func TestSecurityFactorService_RemoveFactor(t *testing.T) {
	var deletedPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	err := svc.RemoveFactor("u1", "f1")
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/factors/f1", deletedPath)
}

func TestSecurityFactorService_RemoveFactor_MissingIDs(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	require.Error(t, svc.RemoveFactor("", "f1"))
	require.Error(t, svc.RemoveFactor("u1", ""))
}

func TestSecurityFactorService_RotateFactor(t *testing.T) {
	var calledPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		resp := AddFactorResponse{
			Factor: AuthFactor{ID: "rotated-f", Type: AuthFactorTypeMTLS},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	got, err := svc.RotateFactor("u1", RotateFactorRequest{
		FactorID: "old-f",
		CertPEM:  "-----BEGIN CERTIFICATE-----\n...",
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/u1/factors/old-f/rotate", calledPath)
	assert.Equal(t, "rotated-f", got.Factor.ID)
}

func TestSecurityFactorService_RelabelFactor(t *testing.T) {
	var gotLabel string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotLabel = body["label"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	err := svc.RelabelFactor("u1", "f1", "My YubiKey")
	require.NoError(t, err)
	assert.Equal(t, "My YubiKey", gotLabel)
}

func TestSecurityFactorService_SetMFAPolicy(t *testing.T) {
	var count int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/tenants/t1/security/mfa-policy", r.URL.Path)
		var body MFAPolicyRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, 2, body.RequireFactorCount)
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	err := svc.SetMFAPolicy(MFAPolicyRequest{TenantID: "t1", RequireFactorCount: 2})
	require.NoError(t, err)
	assert.EqualValues(t, 1, atomic.LoadInt32(&count))
}

func TestSecurityFactorService_SetMFAPolicy_EmptyTenant(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	require.Error(t, svc.SetMFAPolicy(MFAPolicyRequest{}))
}

func TestSecurityFactorService_NoServerConnection(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.ListFactors("u1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoServerConnection)
}

func TestSecurityFactorService_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated"})
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.ListFactors("u1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthenticated")
}

func TestInferPIVVendor(t *testing.T) {
	cases := []struct {
		subject string
		want    string
	}{
		{"CN=YubiKey PIV, O=Yubico AB", "YubiKey PIV"},
		{"CN=NITROKEY3, O=Nitrokey", "Nitrokey PIV"},
		{"CN=GoldKey G4 v2", "GoldKey PIV"},
		{"CN=John Doe, O=ACME Corp", "PIV Card"},
		{"", "PIV Card"},
	}
	for _, c := range cases {
		t.Run(c.subject, func(t *testing.T) {
			assert.Equal(t, c.want, inferPIVVendor(c.subject))
		})
	}
}

// generateSelfSignedAdminPEM creates a combined certificate+private-key PEM
// suitable for tls.X509KeyPair(pemBytes, pemBytes), mirroring the on-disk
// format LoginMTLS expects at ~/.xkey/admin.pem.
func generateSelfSignedAdminPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return append(certPEM, keyPEM...)
}

func TestSecurityFactorService_SetClientCert(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	assert.Nil(t, svc.clientCert)

	certPEM := generateSelfSignedAdminPEM(t, "test-client")
	cert, err := tls.X509KeyPair(certPEM, certPEM)
	require.NoError(t, err)

	svc.SetClientCert(&cert)
	require.NotNil(t, svc.clientCert)
	assert.Equal(t, cert.Certificate, svc.clientCert.Certificate)

	// httpClient must carry the configured client cert into the transport.
	client := svc.httpClient()
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.Len(t, tr.TLSClientConfig.Certificates, 1)
}

func TestSecurityFactorService_ProbeAdminCert_NotExists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	got := svc.ProbeAdminCert()
	assert.Equal(t, map[string]bool{"exists": false}, got)
}

func TestSecurityFactorService_ProbeAdminCert_Exists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".xkey"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".xkey", "admin.pem"), []byte("cert"), 0600))

	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	got := svc.ProbeAdminCert()
	assert.Equal(t, map[string]bool{"exists": true}, got)
}

func TestSecurityFactorService_LoginMTLS_NoAdminCert(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.LoginMTLS()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read admin cert")
}

func TestSecurityFactorService_LoginMTLS_InvalidPEM(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".xkey"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".xkey", "admin.pem"), []byte("not a cert"), 0600))

	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.LoginMTLS()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse admin cert")
}

func TestSecurityFactorService_LoginMTLS_Success(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".xkey"), 0700))
	adminPEM := generateSelfSignedAdminPEM(t, "admin")
	require.NoError(t, os.WriteFile(filepath.Join(home, ".xkey", "admin.pem"), adminPEM, 0600))

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FactorLoginResult{Token: "jwt-token"})
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	result, err := svc.LoginMTLS()
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/auth/mtls/login", gotPath)
	assert.Equal(t, "jwt-token", result.Token)
	assert.NotNil(t, svc.clientCert)
}

func TestSecurityFactorService_LoginFIDO2(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FactorLoginResult{Token: "fido2-token"})
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	result, err := svc.LoginFIDO2("alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", gotBody["username"])
	assert.Equal(t, "fido2-token", result.Token)
}

func TestSecurityFactorService_LoginFIDO2_EmptyUsername(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.LoginFIDO2("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username required")
}

func TestSecurityFactorService_LoginFIDO2CrossDevice(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FactorLoginResult{Token: "cross-device-token"})
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), &PIVService{})
	svc.SetContext(context.Background())

	result, err := svc.LoginFIDO2CrossDevice("bob")
	require.NoError(t, err)
	assert.Equal(t, "bob", gotBody["username"])
	assert.Equal(t, "true", gotBody["cross_device"])
	assert.Equal(t, "cross-device-token", result.Token)
}

func TestSecurityFactorService_LoginFIDO2CrossDevice_ServerError(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.LoginFIDO2CrossDevice("bob")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoServerConnection)
}

func TestSecurityFactorService_LoginPIV_Success(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Authentication")
	pivClient := &mockPIVClient{
		getPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: certPEM,
			Format:      "pem",
		},
	}
	pivSvc := NewPIVService(pivClient, "software")
	pivSvc.SetContext(context.Background())

	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FactorLoginResult{Token: "piv-token"})
	}))
	defer srv.Close()

	svc := NewSecurityFactorService(stubConnectionService(srv), pivSvc)
	svc.SetContext(context.Background())

	result, err := svc.LoginPIV()
	require.NoError(t, err)
	assert.NotEmpty(t, gotBody["cert_pem"])
	assert.Equal(t, "piv-token", result.Token)
}

func TestSecurityFactorService_LoginPIV_NoCert(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	svc.SetContext(context.Background())

	_, err := svc.LoginPIV()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read PIV cert")
}

func TestSecurityFactorService_EnumeratePIVCards_Success(t *testing.T) {
	pivClient := &mockPIVClient{
		listPIVSlotsResp: &transport.ListPIVSlotsResponse{
			Slots: []transport.PIVSlotStatus{
				{Slot: "9a", HasCert: true, Subject: "CN=YubiKey PIV, O=Yubico AB", Backend: "software"},
				{Slot: "9c", HasCert: false},
			},
		},
	}
	pivSvc := NewPIVService(pivClient, "software")
	pivSvc.SetContext(context.Background())

	svc := NewSecurityFactorService(NewConnectionService(), pivSvc)
	cards, err := svc.EnumeratePIVCards()
	require.NoError(t, err)
	require.Len(t, cards, 1)
	assert.Equal(t, "software", cards[0].ReaderName)
	assert.Equal(t, "YubiKey PIV", cards[0].CardVendor)
	assert.True(t, cards[0].HasPIVApplet)
}

func TestSecurityFactorService_EnumeratePIVCards_ListError(t *testing.T) {
	pivClient := &mockPIVClient{
		listPIVSlotsErr: errors.New("pcsc: no reader"),
	}
	pivSvc := NewPIVService(pivClient, "software")
	pivSvc.SetContext(context.Background())

	svc := NewSecurityFactorService(NewConnectionService(), pivSvc)
	cards, err := svc.EnumeratePIVCards()
	require.NoError(t, err)
	assert.Empty(t, cards)
}

func TestSecurityFactorService_ReadPIVCertPEM_Success(t *testing.T) {
	certPEM := generatePIVCertPEM(t, "PIV Authentication")
	pivClient := &mockPIVClient{
		getPIVCertResp: &transport.GetPIVCertificateResponse{
			Slot:        "9a",
			Certificate: certPEM,
			Format:      "pem",
		},
	}
	pivSvc := NewPIVService(pivClient, "software")
	pivSvc.SetContext(context.Background())

	svc := NewSecurityFactorService(NewConnectionService(), pivSvc)
	pemStr, err := svc.ReadPIVCertPEM("9a")
	require.NoError(t, err)
	assert.NotEmpty(t, pemStr)
}

func TestSecurityFactorService_ReadPIVCertPEM_Error(t *testing.T) {
	svc := NewSecurityFactorService(NewConnectionService(), &PIVService{})
	_, err := svc.ReadPIVCertPEM("9a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read PIV cert slot 9a")
}
