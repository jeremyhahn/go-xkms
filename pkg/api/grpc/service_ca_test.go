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

package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockCACert implements grpcCAMethodCert for testing.
type mockCACert struct {
	cert *x509.Certificate
	err  error
}

func (m *mockCACert) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw})
	return &transport.GetCACertificateResponse{
		CertificatePEM: certPEM,
		Subject:        m.cert.Subject.String(),
		Issuer:         m.cert.Issuer.String(),
		SerialNumber:   m.cert.SerialNumber.Text(16),
		NotBefore:      m.cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:       m.cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		IsCA:           m.cert.IsCA,
	}, nil
}

// mockCASignCSR implements grpcCAMethodSignCSR.
type mockCASignCSR struct {
	cert   *x509.Certificate
	err    error
	caCert *x509.Certificate
	caErr  error
}

func (m *mockCASignCSR) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw})
	var chainPEM []byte
	if m.caErr == nil && m.caCert != nil {
		chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
	}
	return &transport.SignCSRResponse{
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
		SerialNumber:   m.cert.SerialNumber.Text(16),
	}, nil
}

// mockCAIssue implements grpcCAMethodIssue.
type mockCAIssue struct {
	certPEM   []byte
	chainPEM  []byte
	keyPEM    []byte
	serialHex string
	err       error
}

func (m *mockCAIssue) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &transport.IssueCertificateResponse{
		CertificatePEM: m.certPEM,
		ChainPEM:       m.chainPEM,
		PrivateKeyPEM:  m.keyPEM,
		SerialNumber:   m.serialHex,
	}, nil
}

// mockCARevoke implements grpcCAMethodRevoke.
type mockCARevoke struct {
	err error
}

func (m *mockCARevoke) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &transport.RevokeCertificateResponse{
		Success: true,
		Message: fmt.Sprintf("certificate %s revoked", req.SerialNumber),
	}, nil
}

// mockCACRL implements grpcCAMethodCRL.
type mockCACRL struct {
	crlDER []byte
	err    error
}

func (m *mockCACRL) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: m.crlDER})
	return &transport.GenerateCRLResponse{CRLPEM: crlPEM}, nil
}

// mockCAIsRevoked implements grpcCAMethodIsRevoked.
type mockCAIsRevoked struct {
	revoked bool
	err     error
}

func (m *mockCAIsRevoked) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	resp := &transport.IsRevokedResponse{Revoked: m.revoked}
	if m.revoked {
		resp.Message = "certificate is revoked"
	} else {
		resp.Message = "certificate is not revoked"
	}
	return resp, nil
}

// mockCAAll implements all CA interfaces for multi-method tests.
type mockCAAll struct {
	mockCACert
	mockCARevoke
	mockCACRL
	mockCAIsRevoked
	issueImpl mockCAIssue
	signImpl  mockCASignCSR
}

func (m *mockCAAll) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return m.signImpl.SignCSR(ctx, req)
}

func (m *mockCAAll) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return m.issueImpl.IssueCertificate(ctx, req)
}

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func TestSetCA_GetCA(t *testing.T) {
	old := GetCA()
	defer SetCA(old)

	t.Run("sets and gets CA", func(t *testing.T) {
		mock := &mockCACert{}
		SetCA(mock)
		assert.Equal(t, mock, GetCA())
	})

	t.Run("sets to nil", func(t *testing.T) {
		SetCA(nil)
		assert.Nil(t, GetCA())
	})
}

func TestGetCACertificate(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.GetCACertificate(context.Background(), &pb.GetCACertificateRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when CA does not implement cert getter", func(t *testing.T) {
		old := GetCA()
		SetCA("not-a-ca") // does not implement grpcCAMethodCert
		defer SetCA(old)

		_, err := svc.GetCACertificate(context.Background(), &pb.GetCACertificateRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when CACertificate fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCACert{err: errors.New("cert error")})
		defer SetCA(old)

		_, err := svc.GetCACertificate(context.Background(), &pb.GetCACertificateRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns certificate on success", func(t *testing.T) {
		cert := generateTestCert(t)
		old := GetCA()
		SetCA(&mockCACert{cert: cert})
		defer SetCA(old)

		resp, err := svc.GetCACertificate(context.Background(), &pb.GetCACertificateRequest{})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.CertificatePem)
		assert.Contains(t, string(resp.CertificatePem), "BEGIN CERTIFICATE")
		assert.Contains(t, resp.Subject, "Test CA")
		assert.True(t, resp.IsCa)
		assert.Equal(t, cert.SerialNumber.Text(16), resp.SerialNumber)
	})
}

func TestSignCSR(t *testing.T) {
	svc := NewService(nil, nil, nil)
	cert := generateTestCert(t)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{CsrPem: []byte("csr")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when CSR PEM is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignCSR{})
		defer SetCA(old)

		_, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{CsrPem: nil})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not implement SignCSR", func(t *testing.T) {
		old := GetCA()
		SetCA("not-a-signer")
		defer SetCA(old)

		_, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{CsrPem: []byte("csr")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when signing fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignCSR{err: errors.New("sign failed")})
		defer SetCA(old)

		_, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{CsrPem: []byte("csr")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns signed certificate with chain on success", func(t *testing.T) {
		caCert := generateTestCert(t)
		old := GetCA()
		SetCA(&mockCASignCSR{cert: cert, caCert: caCert})
		defer SetCA(old)

		resp, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{
			CsrPem:       []byte("csr"),
			Profile:      "server",
			ValidityDays: 365,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.CertificatePem)
		assert.NotEmpty(t, resp.ChainPem)
		assert.Equal(t, cert.SerialNumber.Text(16), resp.SerialNumber)
	})

	t.Run("returns signed certificate without chain when CA cert fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignCSR{cert: cert, caErr: errors.New("no ca cert")})
		defer SetCA(old)

		resp, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{CsrPem: []byte("csr")})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.CertificatePem)
		assert.Empty(t, resp.ChainPem)
	})
}

func TestIssueCertificate(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.IssueCertificate(context.Background(), &pb.IssueCertificateRequest{CommonName: "test"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when common name is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssue{})
		defer SetCA(old)

		_, err := svc.IssueCertificate(context.Background(), &pb.IssueCertificateRequest{CommonName: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not implement issue", func(t *testing.T) {
		old := GetCA()
		SetCA("not-an-issuer")
		defer SetCA(old)

		_, err := svc.IssueCertificate(context.Background(), &pb.IssueCertificateRequest{CommonName: "test"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when issuance fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssue{err: errors.New("issue failed")})
		defer SetCA(old)

		_, err := svc.IssueCertificate(context.Background(), &pb.IssueCertificateRequest{CommonName: "test"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns certificate on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssue{
			certPEM:   []byte("cert-pem"),
			chainPEM:  []byte("chain-pem"),
			keyPEM:    []byte("key-pem"),
			serialHex: "abc123",
		})
		defer SetCA(old)

		resp, err := svc.IssueCertificate(context.Background(), &pb.IssueCertificateRequest{
			CommonName:   "test.example.com",
			Organization: "Test Org",
			Sans:         []string{"alt.example.com"},
			ValidityDays: 365,
			Profile:      "server",
			Algorithm:    "ECDSA",
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-pem"), resp.CertificatePem)
		assert.Equal(t, []byte("chain-pem"), resp.ChainPem)
		assert.Equal(t, []byte("key-pem"), resp.PrivateKeyPem)
		assert.Equal(t, "abc123", resp.SerialNumber)
	})
}

func TestRevokeCertificate(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.RevokeCertificate(context.Background(), &pb.RevokeCertificateRequest{SerialNumber: "abc"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when serial number is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCARevoke{})
		defer SetCA(old)

		_, err := svc.RevokeCertificate(context.Background(), &pb.RevokeCertificateRequest{SerialNumber: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not implement revoke", func(t *testing.T) {
		old := GetCA()
		SetCA("not-a-revoker")
		defer SetCA(old)

		_, err := svc.RevokeCertificate(context.Background(), &pb.RevokeCertificateRequest{SerialNumber: "abc"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when serial number is invalid hex", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCARevoke{})
		defer SetCA(old)

		_, err := svc.RevokeCertificate(context.Background(), &pb.RevokeCertificateRequest{SerialNumber: "not-hex"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when revocation fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCARevoke{err: errors.New("revoke failed")})
		defer SetCA(old)

		_, err := svc.RevokeCertificate(context.Background(), &pb.RevokeCertificateRequest{SerialNumber: "abc"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("revokes certificate on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCARevoke{})
		defer SetCA(old)

		resp, err := svc.RevokeCertificate(context.Background(), &pb.RevokeCertificateRequest{
			SerialNumber: "0xabc",
			Reason:       1,
		})
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "0xabc")
	})
}

func TestGenerateCRL(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.GenerateCRL(context.Background(), &pb.GenerateCRLRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when CA does not implement CRL", func(t *testing.T) {
		old := GetCA()
		SetCA("not-a-crl-generator")
		defer SetCA(old)

		_, err := svc.GenerateCRL(context.Background(), &pb.GenerateCRLRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when CRL generation fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCACRL{err: errors.New("crl failed")})
		defer SetCA(old)

		_, err := svc.GenerateCRL(context.Background(), &pb.GenerateCRLRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns CRL on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCACRL{crlDER: []byte("crl-data")})
		defer SetCA(old)

		resp, err := svc.GenerateCRL(context.Background(), &pb.GenerateCRLRequest{})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.CrlPem)
		assert.Contains(t, string(resp.CrlPem), "X509 CRL")
	})
}

func TestIsRevoked(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: "abc"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when serial number is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIsRevoked{})
		defer SetCA(old)

		_, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not implement IsRevoked", func(t *testing.T) {
		old := GetCA()
		SetCA("not-a-checker")
		defer SetCA(old)

		_, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: "abc"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when serial is invalid hex", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIsRevoked{})
		defer SetCA(old)

		_, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: "not-hex"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when check fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIsRevoked{err: errors.New("check failed")})
		defer SetCA(old)

		_, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: "abc"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns revoked=true when certificate is revoked", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIsRevoked{revoked: true})
		defer SetCA(old)

		resp, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: "abc"})
		require.NoError(t, err)
		assert.True(t, resp.Revoked)
		assert.Contains(t, resp.Message, "is revoked")
	})

	t.Run("returns revoked=false when certificate is not revoked", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIsRevoked{revoked: false})
		defer SetCA(old)

		resp, err := svc.IsRevoked(context.Background(), &pb.IsRevokedRequest{SerialNumber: "abc"})
		require.NoError(t, err)
		assert.False(t, resp.Revoked)
		assert.Contains(t, resp.Message, "not revoked")
	})
}

func TestParseCASerialHex(t *testing.T) {
	t.Run("parses plain hex", func(t *testing.T) {
		serial, err := parseCASerialHex("abc")
		require.NoError(t, err)
		assert.Equal(t, "abc", serial.Text(16))
	})

	t.Run("strips 0x prefix", func(t *testing.T) {
		serial, err := parseCASerialHex("0xabc")
		require.NoError(t, err)
		assert.Equal(t, "abc", serial.Text(16))
	})

	t.Run("strips 0X prefix", func(t *testing.T) {
		serial, err := parseCASerialHex("0Xdef")
		require.NoError(t, err)
		assert.Equal(t, "def", serial.Text(16))
	})

	t.Run("returns error for invalid hex", func(t *testing.T) {
		_, err := parseCASerialHex("not-hex-zzzz")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSerialNumber)
	})
}
