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
	"errors"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockCAIssueEK implements grpcCAMethodIssueEK.
type mockCAIssueEK struct {
	resp *transport.IssueEKCertificateResponse
	err  error
}

func (m *mockCAIssueEK) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return m.resp, m.err
}

// mockCAIssueAK implements grpcCAMethodIssueAK.
type mockCAIssueAK struct {
	resp *transport.IssueAKCertificateResponse
	err  error
}

func (m *mockCAIssueAK) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return m.resp, m.err
}

// mockCASignTCGCSR implements grpcCAMethodSignTCGCSR.
type mockCASignTCGCSR struct {
	resp *transport.SignTCGCSRResponse
	err  error
}

func (m *mockCASignTCGCSR) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return m.resp, m.err
}

// mockCAEnrollDevice implements grpcCAMethodEnrollDevice.
type mockCAEnrollDevice struct {
	resp *transport.EnrollDeviceResponse
	err  error
}

func (m *mockCAEnrollDevice) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return m.resp, m.err
}

func TestIssueEKCertificate(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.IssueEKCertificate(context.Background(), &pb.IssueEKCertificateRequest{
			CommonName:  "test",
			EkPublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when common name is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueEK{})
		defer SetCA(old)

		_, err := svc.IssueEKCertificate(context.Background(), &pb.IssueEKCertificateRequest{
			CommonName:  "",
			EkPublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when EK public key is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueEK{})
		defer SetCA(old)

		_, err := svc.IssueEKCertificate(context.Background(), &pb.IssueEKCertificateRequest{
			CommonName: "test",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not support TCG", func(t *testing.T) {
		old := GetCA()
		SetCA("not-tcg-ca")
		defer SetCA(old)

		_, err := svc.IssueEKCertificate(context.Background(), &pb.IssueEKCertificateRequest{
			CommonName:  "test",
			EkPublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when issuance fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueEK{err: errors.New("ek issue failed")})
		defer SetCA(old)

		_, err := svc.IssueEKCertificate(context.Background(), &pb.IssueEKCertificateRequest{
			CommonName:  "test",
			EkPublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns certificate on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueEK{resp: &transport.IssueEKCertificateResponse{
			CertificateDER: []byte("der"),
			CertificatePEM: []byte("pem"),
			SerialNumber:   "abc123",
		}})
		defer SetCA(old)

		resp, err := svc.IssueEKCertificate(context.Background(), &pb.IssueEKCertificateRequest{
			CommonName:   "test",
			Organization: "org",
			EkPublicKey:  []byte("key"),
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("der"), resp.CertificateDer)
		assert.Equal(t, []byte("pem"), resp.CertificatePem)
		assert.Equal(t, "abc123", resp.SerialNumber)
	})
}

func TestIssueAKCertificate(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.IssueAKCertificate(context.Background(), &pb.IssueAKCertificateRequest{
			CommonName: "test",
			PublicKey:  []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when common name is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueAK{})
		defer SetCA(old)

		_, err := svc.IssueAKCertificate(context.Background(), &pb.IssueAKCertificateRequest{
			PublicKey: []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when public key is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueAK{})
		defer SetCA(old)

		_, err := svc.IssueAKCertificate(context.Background(), &pb.IssueAKCertificateRequest{
			CommonName: "test",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not support TCG", func(t *testing.T) {
		old := GetCA()
		SetCA("not-tcg-ca")
		defer SetCA(old)

		_, err := svc.IssueAKCertificate(context.Background(), &pb.IssueAKCertificateRequest{
			CommonName: "test",
			PublicKey:  []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when issuance fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueAK{err: errors.New("ak issue failed")})
		defer SetCA(old)

		_, err := svc.IssueAKCertificate(context.Background(), &pb.IssueAKCertificateRequest{
			CommonName: "test",
			PublicKey:  []byte("key"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns certificate on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAIssueAK{resp: &transport.IssueAKCertificateResponse{
			CertificateDER: []byte("der"),
			CertificatePEM: []byte("pem"),
			SerialNumber:   "def456",
		}})
		defer SetCA(old)

		resp, err := svc.IssueAKCertificate(context.Background(), &pb.IssueAKCertificateRequest{
			CommonName:   "test",
			Organization: "org",
			PublicKey:    []byte("key"),
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("der"), resp.CertificateDer)
		assert.Equal(t, []byte("pem"), resp.CertificatePem)
		assert.Equal(t, "def456", resp.SerialNumber)
	})
}

func TestSignTCGCSR(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.SignTCGCSR(context.Background(), &pb.SignTCGCSRRequest{
			CommonName: "test",
			TcgCsr:     []byte("csr"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when common name is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignTCGCSR{})
		defer SetCA(old)

		_, err := svc.SignTCGCSR(context.Background(), &pb.SignTCGCSRRequest{TcgCsr: []byte("csr")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when TCG CSR is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignTCGCSR{})
		defer SetCA(old)

		_, err := svc.SignTCGCSR(context.Background(), &pb.SignTCGCSRRequest{CommonName: "test"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not support TCG", func(t *testing.T) {
		old := GetCA()
		SetCA("not-tcg-ca")
		defer SetCA(old)

		_, err := svc.SignTCGCSR(context.Background(), &pb.SignTCGCSRRequest{
			CommonName: "test",
			TcgCsr:     []byte("csr"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when signing fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignTCGCSR{err: errors.New("sign failed")})
		defer SetCA(old)

		_, err := svc.SignTCGCSR(context.Background(), &pb.SignTCGCSRRequest{
			CommonName: "test",
			TcgCsr:     []byte("csr"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns certificates on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCASignTCGCSR{resp: &transport.SignTCGCSRResponse{
			IAKCertDER:    []byte("iak-der"),
			IDevIDCertDER: []byte("idevid-der"),
		}})
		defer SetCA(old)

		resp, err := svc.SignTCGCSR(context.Background(), &pb.SignTCGCSRRequest{
			CommonName:   "test",
			Organization: "org",
			TcgCsr:       []byte("csr"),
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("iak-der"), resp.IakCertDer)
		assert.Equal(t, []byte("idevid-der"), resp.IdevidCertDer)
	})
}

func TestEnrollDevice(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when CA not configured", func(t *testing.T) {
		old := GetCA()
		SetCA(nil)
		defer SetCA(old)

		_, err := svc.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{
			CommonName: "test",
			PackedCsr:  []byte("csr"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when common name is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAEnrollDevice{})
		defer SetCA(old)

		_, err := svc.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{PackedCsr: []byte("csr")})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when packed CSR is empty", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAEnrollDevice{})
		defer SetCA(old)

		_, err := svc.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{CommonName: "test"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when CA does not support TCG", func(t *testing.T) {
		old := GetCA()
		SetCA("not-tcg-ca")
		defer SetCA(old)

		_, err := svc.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{
			CommonName: "test",
			PackedCsr:  []byte("csr"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("returns error when enrollment fails", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAEnrollDevice{err: errors.New("enroll failed")})
		defer SetCA(old)

		_, err := svc.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{
			CommonName: "test",
			PackedCsr:  []byte("csr"),
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})

	t.Run("returns enrollment response on success", func(t *testing.T) {
		old := GetCA()
		SetCA(&mockCAEnrollDevice{resp: &transport.EnrollDeviceResponse{
			IAKCertDER:      []byte("iak-der"),
			IDevIDCertDER:   []byte("idevid-der"),
			CredentialBlob:  []byte("cred-blob"),
			EncryptedSecret: []byte("enc-secret"),
			PlainSecret:     []byte("plain-secret"),
		}})
		defer SetCA(old)

		resp, err := svc.EnrollDevice(context.Background(), &pb.EnrollDeviceRequest{
			CommonName:   "test",
			Organization: "org",
			PackedCsr:    []byte("csr"),
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("iak-der"), resp.IakCertDer)
		assert.Equal(t, []byte("idevid-der"), resp.IdevidCertDer)
		assert.Equal(t, []byte("cred-blob"), resp.CredentialBlob)
		assert.Equal(t, []byte("enc-secret"), resp.EncryptedSecret)
		assert.Equal(t, []byte("plain-secret"), resp.PlainSecret)
	})
}
