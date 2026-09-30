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

// module_ca_test.go is the go-xkms#951 regression test for the unified
// server's gRPC surface: Module.keystore must wire the resolved
// XKMSService as the keystore gRPC service's CA servicer when that
// XKMSService has a CA configured, and leave CA RPCs answering
// codes.Unavailable when it does not.
package apimodule

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// mockModuleProviderCA implements pkg/ca/provider.CA, standing in for the
// real *ca.CA the composition root wires into XKMSService.SetCA. Using it
// here exercises the identical delegation chain production traffic uses:
// the gRPC handler forwards to *xkms.XKMSService, which forwards to this
// provider.CA.
type mockModuleProviderCA struct {
	cert *x509.Certificate
}

func (m *mockModuleProviderCA) CABundle() ([]byte, error)                 { return nil, nil }
func (m *mockModuleProviderCA) CACertificate() (*x509.Certificate, error) { return m.cert, nil }
func (m *mockModuleProviderCA) SignCSRRaw(context.Context, []byte, string, int) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockModuleProviderCA) SignCSRWithSPIFFE(context.Context, []byte, string, int, string, string, string, string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockModuleProviderCA) IssueCertificateRaw(context.Context, string, string, []string, int, string, string, string) ([]byte, []byte, []byte, string, error) {
	return nil, nil, nil, "", nil
}
func (m *mockModuleProviderCA) Revoke(context.Context, *big.Int, int) error { return nil }
func (m *mockModuleProviderCA) CertificateTenant(context.Context, *big.Int) (string, error) {
	return "", nil
}
func (m *mockModuleProviderCA) GenerateCRL(context.Context) ([]byte, error) { return nil, nil }
func (m *mockModuleProviderCA) CRL(context.Context) ([]byte, error)         { return nil, nil }
func (m *mockModuleProviderCA) IsRevoked(*big.Int) (bool, error)            { return false, nil }
func (m *mockModuleProviderCA) Identity() string                            { return "mock-ca" }
func (m *mockModuleProviderCA) IsInitialized() bool                         { return true }

var _ provider.CA = (*mockModuleProviderCA)(nil)

// generateModuleTestCACert creates a self-signed RSA CA certificate for the
// tests in this file.
func generateModuleTestCACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Module E2E Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestModule_GetCACertificate_NoCA verifies the module's gRPC
// KeystoreService answers codes.Unavailable for a CA RPC when the resolved
// XKMSService has no CA configured.
func TestModule_GetCACertificate_NoCA(t *testing.T) {
	m, err := NewModule(func() *xkms.XKMSService { return &xkms.XKMSService{} })
	require.NoError(t, err)

	client := startBufconnModule(t, m)
	ctx := context.Background()

	_, err = client.GetCACertificate(ctx, &pb.GetCACertificateRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code())
}

// TestModule_GetCACertificate_WithCA verifies the module's gRPC
// KeystoreService serves a CA RPC when the resolved XKMSService has a CA
// configured (go-xkms#951 regression: Module.keystore never wired a CA
// servicer at all before this fix, so this RPC always answered
// Unavailable in production).
func TestModule_GetCACertificate_WithCA(t *testing.T) {
	cert := generateModuleTestCACert(t)
	svc := &xkms.XKMSService{}
	svc.SetCA(&mockModuleProviderCA{cert: cert})

	m, err := NewModule(func() *xkms.XKMSService { return svc })
	require.NoError(t, err)

	client := startBufconnModule(t, m)
	ctx := context.Background()

	resp, err := client.GetCACertificate(ctx, &pb.GetCACertificateRequest{})
	require.NoError(t, err)
	require.Equal(t, cert.SerialNumber.Text(16), resp.SerialNumber)
}
