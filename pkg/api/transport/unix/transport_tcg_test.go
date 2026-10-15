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

package unix

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestTCGCA_CallsItsRPC proves each TCG CA operation travels the socket as
// its gRPC call, carrying the request fields and returning the reply's.
func TestTCGCA_CallsItsRPC(t *testing.T) {
	ctx := context.Background()

	t.Run("IssueEKCertificate", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.IssueEKCertificateResponse{CertificateDer: []byte{1}, SerialNumber: "0a"}}
		resp, err := rec.connect(t).IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
			CommonName: "tpm-1", Organization: "acme", EKPublicKey: []byte{2},
		})
		require.NoError(t, err)

		var sent pb.IssueEKCertificateRequest
		assert.Equal(t, "IssueEKCertificate", rec.request(t, &sent))
		assert.Equal(t, "tpm-1", sent.GetCommonName())
		assert.Equal(t, "acme", sent.GetOrganization())
		assert.Equal(t, []byte{2}, sent.GetEkPublicKey())
		assert.Equal(t, []byte{1}, resp.CertificateDER)
		assert.Equal(t, "0a", resp.SerialNumber)
	})

	t.Run("IssueAKCertificate", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.IssueAKCertificateResponse{CertificatePem: []byte("PEM"), SerialNumber: "0b"}}
		resp, err := rec.connect(t).IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
			CommonName: "ak-1", PublicKey: []byte{3},
		})
		require.NoError(t, err)

		var sent pb.IssueAKCertificateRequest
		assert.Equal(t, "IssueAKCertificate", rec.request(t, &sent))
		assert.Equal(t, "ak-1", sent.GetCommonName())
		assert.Equal(t, []byte{3}, sent.GetPublicKey())
		assert.Equal(t, []byte("PEM"), resp.CertificatePEM)
		assert.Equal(t, "0b", resp.SerialNumber)
	})

	t.Run("SignTCGCSR", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.SignTCGCSRResponse{IakCertDer: []byte{4}, IdevidCertDer: []byte{5}}}
		resp, err := rec.connect(t).SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
			CommonName: "dev-1", TCGCSR: []byte{6},
		})
		require.NoError(t, err)

		var sent pb.SignTCGCSRRequest
		assert.Equal(t, "SignTCGCSR", rec.request(t, &sent))
		assert.Equal(t, "dev-1", sent.GetCommonName())
		assert.Equal(t, []byte{6}, sent.GetTcgCsr())
		assert.Equal(t, []byte{4}, resp.IAKCertDER)
		assert.Equal(t, []byte{5}, resp.IDevIDCertDER)
	})

	t.Run("EnrollDevice", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.EnrollDeviceResponse{
			IakCertDer: []byte{7}, IdevidCertDer: []byte{8}, CredentialBlob: []byte{9}, EncryptedSecret: []byte{10},
		}}
		resp, err := rec.connect(t).EnrollDevice(ctx, &transport.EnrollDeviceRequest{
			CommonName: "dev-2", PackedCSR: []byte{11},
		})
		require.NoError(t, err)

		var sent pb.EnrollDeviceRequest
		assert.Equal(t, "EnrollDevice", rec.request(t, &sent))
		assert.Equal(t, "dev-2", sent.GetCommonName())
		assert.Equal(t, []byte{11}, sent.GetPackedCsr())
		assert.Equal(t, []byte{7}, resp.IAKCertDER)
		assert.Equal(t, []byte{8}, resp.IDevIDCertDER)
		assert.Equal(t, []byte{9}, resp.CredentialBlob)
		assert.Equal(t, []byte{10}, resp.EncryptedSecret)
	})

	t.Run("IssueLAKCertificate", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.IssueLAKCertificateResponse{CertificateDer: []byte{1, 2}, SerialNumber: "0c"}}
		resp, err := rec.connect(t).IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{
			TPMManufacturer:    "IFX",
			SignatureAlgorithm: int(x509.ECDSAWithSHA256),
			Nonce:              []byte{12},
		})
		require.NoError(t, err)

		var sent pb.IssueLAKCertificateRequest
		assert.Equal(t, "IssueLAKCertificate", rec.request(t, &sent))
		assert.Equal(t, "IFX", sent.GetTpmManufacturer())
		assert.Equal(t, int32(x509.ECDSAWithSHA256), sent.GetSignatureAlgorithm())
		assert.Equal(t, []byte{12}, sent.GetNonce())
		assert.Equal(t, []byte{1, 2}, resp.CertificateDER)
		assert.Equal(t, "0c", resp.SerialNumber)
	})
}

// tcgCalls invokes every TCG CA operation with an empty request.
func tcgCalls(ctx context.Context, tr *Transport) map[string]func() error {
	return map[string]func() error{
		"IssueEKCertificate": func() error {
			_, err := tr.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{})
			return err
		},
		"IssueAKCertificate": func() error {
			_, err := tr.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{})
			return err
		},
		"SignTCGCSR": func() error {
			_, err := tr.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{})
			return err
		},
		"EnrollDevice": func() error {
			_, err := tr.EnrollDevice(ctx, &transport.EnrollDeviceRequest{})
			return err
		},
		"IssueLAKCertificate": func() error {
			_, err := tr.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{})
			return err
		},
	}
}

func TestTCGCA_ServerErrorSurfaces(t *testing.T) {
	rec := &rpcRecorder{err: status.Error(codes.PermissionDenied, "iak not trusted")}
	tr := rec.connect(t)

	for name, call := range tcgCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "iak not trusted")
			assert.Equal(t, name, rec.request(t, nil))
		})
	}
}

func TestTCGCA_NotConnected(t *testing.T) {
	for name, call := range tcgCalls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
