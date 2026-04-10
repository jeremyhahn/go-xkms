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

package pairing

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSharingClient extends mockTransportClient with configurable responses for
// import, export, certificate, and key material operations used by the sharing handlers.
type mockSharingClient struct {
	mockTransportClient

	importKeyResp *transport.ImportKeyResponse
	importKeyErr  error

	saveCertErr error

	getCertResp *transport.GetCertificateResponse
	getCertErr  error

	exportKeyMaterialResp *transport.ExportKeyMaterialResponse
	exportKeyMaterialErr  error
}

func (m *mockSharingClient) ImportKey(_ context.Context, _ *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return m.importKeyResp, m.importKeyErr
}

func (m *mockSharingClient) SaveCertificate(_ context.Context, _ *transport.SaveCertificateRequest) error {
	return m.saveCertErr
}

func (m *mockSharingClient) GetCertificate(_ context.Context, _, _ string) (*transport.GetCertificateResponse, error) {
	return m.getCertResp, m.getCertErr
}

func (m *mockSharingClient) ExportKeyMaterial(_ context.Context, _ *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return m.exportKeyMaterialResp, m.exportKeyMaterialErr
}

// --- handleSharePublicKey tests ---

func TestBridge_HandleSharePublicKey_Success(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-phone-key-1",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "phone-key-1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYH..."),
		Algorithm:    "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSharePublicKeyResult](t, resp)
	assert.True(t, result.Accepted)
	assert.Equal(t, "shared-phone-key-1", result.ImportID)
	assert.Equal(t, "software", result.Backend)
}

func TestBridge_HandleSharePublicKey_InvalidParams(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemoteSharePublicKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleSharePublicKey_EmptyPublicKey(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:     "key1",
		Algorithm: "ECDSA-P256",
		// PublicKeyPEM intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidPublicKey)
}

func TestBridge_HandleSharePublicKey_EmptyAlgorithm(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "key1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		// Algorithm intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleSharePublicKey_BackendDenied(t *testing.T) {
	client := &mockSharingClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "key1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		Algorithm:    "ECDSA-P256",
		Backend:      "restricted",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_HandleSharePublicKey_ImportError(t *testing.T) {
	client := &mockSharingClient{
		importKeyErr: errors.New("import failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "key1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		Algorithm:    "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_HandleSharePublicKey_WithCertificate(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-with-cert",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:          "key1",
		PublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ncert..."),
		Algorithm:      "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSharePublicKeyResult](t, resp)
	assert.True(t, result.Accepted)
}

func TestBridge_HandleSharePublicKey_WithCertificateError(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-cert-fail",
		},
		saveCertErr: errors.New("cert save failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:          "key1",
		PublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\ncert..."),
		Algorithm:      "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	// Should succeed even if cert save fails (cert is optional).
	result := decodeResult[RemoteSharePublicKeyResult](t, resp)
	assert.True(t, result.Accepted)
}

func TestBridge_HandleSharePublicKey_WithLabel(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "custom-label",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "key1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		Algorithm:    "ECDSA-P256",
		Label:        "custom-label",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSharePublicKeyResult](t, resp)
	assert.True(t, result.Accepted)
	assert.Equal(t, "custom-label", result.ImportID)
}

func TestBridge_HandleSharePublicKey_DefaultBackend(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-default-backend",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "key1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\ntest..."),
		Algorithm:    "ECDSA-P256",
		// Backend intentionally empty to test default
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSharePublicKeyResult](t, resp)
	assert.Equal(t, "software", result.Backend)
}

// --- handleShareSymmetric tests ---

func TestBridge_HandleShareSymmetric_Success(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-sym-key-1",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-1",
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  "AES-256-GCM",
		KeySize:    256,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteShareSymmetricResult](t, resp)
	assert.True(t, result.Accepted)
	assert.Equal(t, "shared-sym-key-1", result.ImportID)
	assert.Equal(t, "software", result.Backend)
}

func TestBridge_HandleShareSymmetric_InvalidParams(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleShareSymmetric_EmptyWrappedKey(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:     "sym-1",
		Algorithm: "AES-256-GCM",
		// WrappedKey intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleShareSymmetric_EmptyAlgorithm(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-1",
		WrappedKey: []byte("wrapped-material"),
		// Algorithm intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleShareSymmetric_BackendDenied(t *testing.T) {
	client := &mockSharingClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-1",
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  "AES-256-GCM",
		Backend:    "restricted",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_HandleShareSymmetric_ImportError(t *testing.T) {
	client := &mockSharingClient{
		importKeyErr: errors.New("import failed"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-1",
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  "AES-256-GCM",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_HandleShareSymmetric_WithLabel(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "my-sym-label",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-1",
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  "AES-256-GCM",
		Label:      "my-sym-label",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteShareSymmetricResult](t, resp)
	assert.True(t, result.Accepted)
}

func TestBridge_HandleShareSymmetric_DefaultBackend(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-sym-default",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-1",
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  "AES-256-GCM",
		// Backend intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteShareSymmetricResult](t, resp)
	assert.Equal(t, "software", result.Backend)
}

// --- handleImportSharedKey tests ---

func TestBridge_HandleImportSharedKey_PublicKeySuccess(t *testing.T) {
	client := &mockSharingClient{
		mockTransportClient: mockTransportClient{
			getKeyResp: &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:     "key1",
					Backend:   "software",
					Algorithm: "ECDSA-P256",
				},
				PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest...",
			},
		},
		getCertResp: &transport.GetCertificateResponse{
			CertificatePEM: "-----BEGIN CERTIFICATE-----\ncert...",
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteImportSharedKeyResult](t, resp)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	assert.Equal(t, "public", result.KeyType)
	assert.True(t, result.Exportable)
	assert.NotEmpty(t, result.PublicKeyPEM)
	assert.NotEmpty(t, result.CertificatePEM)
}

func TestBridge_HandleImportSharedKey_InvalidParams(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleImportSharedKey_MissingBackend(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		KeyID: "key1",
		// Backend intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleImportSharedKey_MissingKeyID(t *testing.T) {
	client := &mockSharingClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		// KeyID intentionally empty
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleImportSharedKey_BackendDenied(t *testing.T) {
	client := &mockSharingClient{}
	config := &BridgeConfig{
		DeniedBackends: []string{"restricted"},
		Logger:         testLogger(),
	}

	b, err := NewBridge(client, config)
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "restricted",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeBackendDenied)
}

func TestBridge_HandleImportSharedKey_GetKeyError(t *testing.T) {
	client := &mockSharingClient{
		mockTransportClient: mockTransportClient{
			getKeyErr: errors.New("key not found"),
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInternalError)
}

func TestBridge_HandleImportSharedKey_SymmetricKey(t *testing.T) {
	client := &mockSharingClient{
		mockTransportClient: mockTransportClient{
			getKeyResp: &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:     "sym-key",
					Backend:   "software",
					Algorithm: "AES-256-GCM",
				},
			},
		},
		getCertErr: errors.New("no cert"),
		exportKeyMaterialResp: &transport.ExportKeyMaterialResponse{
			KeyMaterial: []byte("exported-material"),
			KeySize:     256,
		},
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		KeyID:   "sym-key",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteImportSharedKeyResult](t, resp)
	assert.Equal(t, "AES-256-GCM", result.Algorithm)
	assert.Equal(t, "symmetric", result.KeyType)
	assert.True(t, result.Exportable)
	assert.NotEmpty(t, result.WrappedKey)
	assert.Equal(t, 256, result.KeySize)
}

func TestBridge_HandleImportSharedKey_SymmetricExportError(t *testing.T) {
	client := &mockSharingClient{
		mockTransportClient: mockTransportClient{
			getKeyResp: &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:     "sym-key",
					Backend:   "software",
					Algorithm: "AES-256-GCM",
				},
			},
		},
		getCertErr:           errors.New("no cert"),
		exportKeyMaterialErr: errors.New("export denied"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		KeyID:   "sym-key",
	})
	resp := b.HandleRequest(context.Background(), req)

	// Should still succeed, just without wrapped key material.
	result := decodeResult[RemoteImportSharedKeyResult](t, resp)
	assert.Equal(t, "AES-256-GCM", result.Algorithm)
	assert.False(t, result.Exportable)
}

func TestBridge_HandleImportSharedKey_NoPublicKey(t *testing.T) {
	client := &mockSharingClient{
		mockTransportClient: mockTransportClient{
			getKeyResp: &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:     "key1",
					Backend:   "software",
					Algorithm: "ECDSA-P256",
				},
				// PublicKeyPEM intentionally empty
			},
		},
		getCertErr: errors.New("no cert"),
	}

	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		KeyID:   "key1",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteImportSharedKeyResult](t, resp)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	// No public key available, so KeyType and Exportable remain zero values.
	assert.Empty(t, result.KeyType)
	assert.False(t, result.Exportable)
}

// --- Sharing audit logging tests ---

func TestBridge_HandleSharePublicKey_WithAuditLogger(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-phone-key-audit",
		},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSharePublicKey, RemoteSharePublicKeyParams{
		KeyID:        "phone-key-1",
		PublicKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYH..."),
		Algorithm:    "ECDSA-P256",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSharePublicKeyResult](t, resp)
	assert.True(t, result.Accepted)
	// Verify audit log was called.
	assert.Contains(t, auditLog.keyOps, string(audit.OpKeyCreated))
}

func TestBridge_HandleShareSymmetric_WithAuditLogger(t *testing.T) {
	client := &mockSharingClient{
		importKeyResp: &transport.ImportKeyResponse{
			Success: true,
			KeyID:   "shared-sym-audit",
		},
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteShareSymmetric, RemoteShareSymmetricParams{
		KeyID:      "sym-key-1",
		WrappedKey: []byte("wrapped-material"),
		Algorithm:  "AES-256-GCM",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteShareSymmetricResult](t, resp)
	assert.True(t, result.Accepted)
	assert.Contains(t, auditLog.keyOps, string(audit.OpKeyCreated))
}

func TestBridge_HandleImportSharedKey_WithAuditLogger(t *testing.T) {
	client := &mockSharingClient{
		mockTransportClient: mockTransportClient{
			getKeyResp: &transport.GetKeyResponse{
				KeyInfo: transport.KeyInfo{
					KeyID:     "audit-key",
					Backend:   "software",
					Algorithm: "ECDSA-P256",
				},
				PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest...",
			},
		},
		getCertErr: errors.New("no cert"),
	}

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(client, &BridgeConfig{
		Logger:      testLogger(),
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteImportSharedKey, RemoteImportSharedKeyParams{
		Backend: "software",
		KeyID:   "audit-key",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteImportSharedKeyResult](t, resp)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	assert.Contains(t, auditLog.keyOps, string(audit.OpKeyAccessed))
}

// --- Helper function tests ---

func TestGenerateImportID(t *testing.T) {
	id := generateImportID([]byte("test-key-data"))
	assert.NotEmpty(t, id)
	assert.Len(t, id, 16) // SHA-256 first 8 bytes = 16 hex chars

	// Same input produces same ID (deterministic).
	id2 := generateImportID([]byte("test-key-data"))
	assert.Equal(t, id, id2)

	// Different input produces different ID.
	id3 := generateImportID([]byte("different-key"))
	assert.NotEqual(t, id, id3)
}

func TestIsSymmetricAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      string
		expected bool
	}{
		{"AES-256-GCM", "AES-256-GCM", true},
		{"aes lowercase", "aes-128-cbc", true},
		{"ChaCha20", "ChaCha20-Poly1305", true},
		{"HMAC", "HMAC-SHA256", true},
		{"symmetric", "SYMMETRIC-KEY", true},
		{"ECDSA", "ECDSA-P256", false},
		{"RSA", "RSA-2048", false},
		{"Ed25519", "Ed25519", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isSymmetricAlgorithm(tt.alg))
		})
	}
}
