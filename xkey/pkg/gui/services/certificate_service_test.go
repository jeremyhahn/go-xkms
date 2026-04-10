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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockCertTransportClient implements the subset of transport.Client used
// by CertificateService. It embeds a nil pointer for the full interface
// and only overrides the methods under test.
type mockCertTransportClient struct {
	transport.Client
	backends *transport.ListBackendsResponse
	certs    map[string]*transport.ListCertificatesResponse
	backErr  error
	certErr  map[string]error
}

func (m *mockCertTransportClient) ListBackends(_ context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	if m.backErr != nil {
		return nil, m.backErr
	}
	return m.backends, nil
}

func (m *mockCertTransportClient) ListCertificates(_ context.Context, backend string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	if m.certErr != nil {
		if err, ok := m.certErr[backend]; ok {
			return nil, err
		}
	}
	if m.certs != nil {
		if resp, ok := m.certs[backend]; ok {
			return resp, nil
		}
	}
	return &transport.ListCertificatesResponse{}, nil
}

func TestCertificateService_ListAllCertificates_NoClient(t *testing.T) {
	svc := NewCertificateService()
	svc.SetContext(context.Background())

	result, err := svc.ListAllCertificates()
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrCertServiceNoClient))
}

func TestCertificateService_NewCertificateService(t *testing.T) {
	svc := NewCertificateService()
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestCertificateService_SetContext(t *testing.T) {
	svc := NewCertificateService()
	ctx := context.Background()
	svc.SetContext(ctx)
	// No panic means success.
}

func TestCertificateService_ListAllCertificates_EmptyBackends(t *testing.T) {
	mock := &mockCertTransportClient{
		backends: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{},
		},
	}
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListAllCertificates()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestCertificateService_ListAllCertificates_BackendError(t *testing.T) {
	errBackend := errors.New("test: backend error")
	mock := &mockCertTransportClient{
		backErr: errBackend,
	}
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListAllCertificates()
	assert.Nil(t, result)
	assert.Equal(t, errBackend, err)
}

func TestCertificateService_ListAllCertificates_WithCerts(t *testing.T) {
	certPEM := string(generateTestCertPEM(t))

	mock := &mockCertTransportClient{
		backends: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
			},
		},
		certs: map[string]*transport.ListCertificatesResponse{
			"software": {
				Certificates: []transport.CertificateInfo{
					{
						KeyID:          "test-key",
						CertificatePEM: certPEM,
					},
				},
			},
		},
	}

	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListAllCertificates()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "software", result[0].Backend)
	assert.Equal(t, "test-key", result[0].KeyID)
	assert.NotEmpty(t, result[0].Subject)
	assert.NotEmpty(t, result[0].Issuer)
	assert.NotEmpty(t, result[0].NotBefore)
	assert.NotEmpty(t, result[0].NotAfter)
	assert.NotEmpty(t, result[0].Algorithm)
	assert.NotEmpty(t, result[0].Fingerprint)
	assert.Equal(t, certPEM, result[0].PEM)
	assert.False(t, result[0].IsExpired)
	assert.True(t, result[0].IsCA)
}

func TestCertificateService_ListAllCertificates_CertListError(t *testing.T) {
	errCerts := errors.New("test: cert list error")
	mock := &mockCertTransportClient{
		backends: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
				{ID: "tpm2", Type: "tpm2"},
			},
		},
		certs: map[string]*transport.ListCertificatesResponse{
			"tpm2": {
				Certificates: []transport.CertificateInfo{},
			},
		},
		certErr: map[string]error{
			"software": errCerts,
		},
	}

	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	// Should not fail entirely, just skip the errored backend.
	result, err := svc.ListAllCertificates()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestCertificateService_ListAllCertificates_InvalidPEM(t *testing.T) {
	mock := &mockCertTransportClient{
		backends: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
			},
		},
		certs: map[string]*transport.ListCertificatesResponse{
			"software": {
				Certificates: []transport.CertificateInfo{
					{
						KeyID:          "bad-cert",
						CertificatePEM: "not-valid-pem",
					},
				},
			},
		},
	}

	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListAllCertificates()
	require.NoError(t, err)
	require.Len(t, result, 1)
	// With invalid PEM, we still get the basic info, just no parsed X.509 fields.
	assert.Equal(t, "software", result[0].Backend)
	assert.Equal(t, "bad-cert", result[0].KeyID)
	assert.Empty(t, result[0].NotBefore)
	assert.Empty(t, result[0].Fingerprint)
}

func TestCertificateService_ListAllCertificates_MultipleBackends(t *testing.T) {
	certPEM := string(generateTestCertPEM(t))

	mock := &mockCertTransportClient{
		backends: &transport.ListBackendsResponse{
			Backends: []transport.BackendInfo{
				{ID: "software", Type: "software"},
				{ID: "tpm2", Type: "tpm2"},
			},
		},
		certs: map[string]*transport.ListCertificatesResponse{
			"software": {
				Certificates: []transport.CertificateInfo{
					{KeyID: "key-1", CertificatePEM: certPEM},
				},
			},
			"tpm2": {
				Certificates: []transport.CertificateInfo{
					{KeyID: "key-2", CertificatePEM: certPEM},
				},
			},
		},
	}

	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListAllCertificates()
	require.NoError(t, err)
	require.Len(t, result, 2)

	// Verify backends are preserved.
	backends := make(map[string]bool)
	for _, r := range result {
		backends[r.Backend] = true
	}
	assert.True(t, backends["software"])
	assert.True(t, backends["tpm2"])
}

// --- ListCertificates (single-backend) tests ---

func TestCertificateService_ListCertificates_NoClient(t *testing.T) {
	svc := NewCertificateService()
	svc.SetContext(context.Background())

	result, err := svc.ListCertificates("software")
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrCertServiceNoClient))
}

func TestCertificateService_ListCertificates_EmptyBackend(t *testing.T) {
	mock := &mockCertTransportClient{
		certs: map[string]*transport.ListCertificatesResponse{
			"software": {Certificates: []transport.CertificateInfo{}},
		},
	}
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListCertificates("software")
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestCertificateService_ListCertificates_WithCerts(t *testing.T) {
	certPEM := string(generateTestCertPEM(t))

	mock := &mockCertTransportClient{
		certs: map[string]*transport.ListCertificatesResponse{
			"software": {
				Certificates: []transport.CertificateInfo{
					{KeyID: "key-a", CertificatePEM: certPEM},
					{KeyID: "key-b", CertificatePEM: certPEM},
				},
			},
		},
	}
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListCertificates("software")
	require.NoError(t, err)
	require.Len(t, result, 2)

	for _, r := range result {
		assert.Equal(t, "software", r.Backend)
		assert.NotEmpty(t, r.KeyID)
		assert.NotEmpty(t, r.Subject)
		assert.NotEmpty(t, r.Fingerprint)
		assert.False(t, r.IsExpired)
	}
}

func TestCertificateService_ListCertificates_BackendError(t *testing.T) {
	errCert := errors.New("test: cert error")
	mock := &mockCertTransportClient{
		certErr: map[string]error{
			"software": errCert,
		},
	}
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	result, err := svc.ListCertificates("software")
	assert.Nil(t, result)
	assert.Equal(t, errCert, err)
}

func TestCertificateService_ListCertificates_InvalidPEM(t *testing.T) {
	mock := &mockCertTransportClient{
		certs: map[string]*transport.ListCertificatesResponse{
			"tpm2": {
				Certificates: []transport.CertificateInfo{
					{KeyID: "bad", CertificatePEM: "not-pem"},
				},
			},
		},
	}
	svc := NewCertificateService()
	svc.SetContext(context.Background())
	svc.SetClient(mock)

	// Invalid PEM still produces a result; X.509 fields are simply absent.
	result, err := svc.ListCertificates("tpm2")
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "tpm2", result[0].Backend)
	assert.Equal(t, "bad", result[0].KeyID)
	assert.Empty(t, result[0].Fingerprint)
}

func TestCertificateService_ListCertificates_NilContext(t *testing.T) {
	certPEM := string(generateTestCertPEM(t))

	mock := &mockCertTransportClient{
		certs: map[string]*transport.ListCertificatesResponse{
			"software": {
				Certificates: []transport.CertificateInfo{
					{KeyID: "k1", CertificatePEM: certPEM},
				},
			},
		},
	}
	// Do NOT call SetContext so ctx remains nil; the method must fall back to
	// context.Background() without panicking.
	svc := NewCertificateService()
	svc.SetClient(mock)

	result, err := svc.ListCertificates("software")
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "software", result[0].Backend)
}
