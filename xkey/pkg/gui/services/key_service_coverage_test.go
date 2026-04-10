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
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test audit logger for key service coverage tests
// ---------------------------------------------------------------------------

type keyCoverageAuditLogger struct {
	entries []audit.Entry
}

func (l *keyCoverageAuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *keyCoverageAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (l *keyCoverageAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *keyCoverageAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {
}
func (l *keyCoverageAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) {
}
func (l *keyCoverageAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *keyCoverageAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {
}
func (l *keyCoverageAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *keyCoverageAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

// ---------------------------------------------------------------------------
// Mock registry for backend listing tests
// ---------------------------------------------------------------------------

type mockRegistry struct {
	backends []*backendregistry.RegisteredBackend
}

func (m *mockRegistry) Register(b *backendregistry.RegisteredBackend) error { return nil }
func (m *mockRegistry) Unregister(id string) error                          { return nil }
func (m *mockRegistry) Get(id string) (*backendregistry.RegisteredBackend, error) {
	for _, b := range m.backends {
		if b.ID == id {
			return b, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *mockRegistry) List() []*backendregistry.RegisteredBackend { return m.backends }
func (m *mockRegistry) ListByCapability(cap backendregistry.Capability) []*backendregistry.RegisteredBackend {
	return nil
}
func (m *mockRegistry) ListByCategory(cat backendregistry.BackendCategory) []*backendregistry.RegisteredBackend {
	return nil
}
func (m *mockRegistry) ListByLocation(loc backendregistry.BackendLocation) []*backendregistry.RegisteredBackend {
	return nil
}
func (m *mockRegistry) GetDefault(feature backendregistry.Capability) (*backendregistry.RegisteredBackend, error) {
	return nil, nil
}
func (m *mockRegistry) SetDefault(feature backendregistry.Capability, id string) error { return nil }
func (m *mockRegistry) Subscribe(handler backendregistry.EventHandler) int             { return 0 }
func (m *mockRegistry) Unsubscribe(id int)                                             {}
func (m *mockRegistry) UpdateDisplayName(_ string, _ string) error                     { return nil }
func (m *mockRegistry) Close() error                                                   { return nil }
func (m *mockRegistry) UpdateState(id string, state backendregistry.BackendState) error {
	return nil
}

// ---------------------------------------------------------------------------
// Constructor and setter tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_NewKeyService(t *testing.T) {
	svc := NewKeyService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.Nil(t, svc.clientFunc)
	assert.Nil(t, svc.localClient)
	assert.Nil(t, svc.auditLogger)
	assert.Nil(t, svc.registry)
}

func TestKeyService_Coverage_SetContext(t *testing.T) {
	svc := NewKeyService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestKeyService_Coverage_SetClientFunc(t *testing.T) {
	svc := NewKeyService()
	_ = func() *mockClient { return nil }
	// Can't directly compare funcs, just verify it doesn't panic and is set.
	svc.SetClientFunc(nil)
	assert.Nil(t, svc.clientFunc)
}

func TestKeyService_Coverage_SetAuditLogger(t *testing.T) {
	svc := NewKeyService()
	logger := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(logger)
	assert.NotNil(t, svc.auditLogger)
}

func TestKeyService_Coverage_SetLocalClient(t *testing.T) {
	svc := NewKeyService()
	mc := &mockClient{}
	svc.SetLocalClient(mc)
	assert.NotNil(t, svc.localClient)
}

func TestKeyService_Coverage_SetRegistry(t *testing.T) {
	svc := NewKeyService()
	reg := &mockRegistry{}
	svc.SetRegistry(reg)
	assert.NotNil(t, svc.registry)
}

// ---------------------------------------------------------------------------
// getClient tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_GetClient_LocalSuccess(t *testing.T) {
	svc := NewKeyService()
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	client, err := svc.getClient("local")
	require.NoError(t, err)
	assert.Equal(t, mc, client)
}

func TestKeyService_Coverage_GetClient_LocalNilError(t *testing.T) {
	svc := NewKeyService()

	client, err := svc.getClient("local")
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrKeyServiceNoLocalClient)
}

func TestKeyService_Coverage_GetClient_ServerNilFuncError(t *testing.T) {
	svc := NewKeyService()

	client, err := svc.getClient("server")
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_GetClient_ServerFuncReturnsNil(t *testing.T) {
	svc := NewKeyService()
	svc.SetClientFunc(func() xkms.Client { return nil })

	client, err := svc.getClient("server")
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_GetClient_ServerSuccess(t *testing.T) {
	svc := NewKeyService()
	mc := &mockClient{}
	svc.SetClientFunc(func() xkms.Client { return mc })

	client, err := svc.getClient("server")
	require.NoError(t, err)
	assert.Equal(t, mc, client)
}

// ---------------------------------------------------------------------------
// convertRegistryCapabilities tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ConvertRegistryCapabilities_Signing(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSigning: true,
	}
	bc := convertRegistryCapabilities(caps)
	assert.True(t, bc.Signing)
	assert.True(t, bc.Keys)
}

func TestKeyService_Coverage_ConvertRegistryCapabilities_Encryption(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapEncryption: true,
	}
	bc := convertRegistryCapabilities(caps)
	assert.True(t, bc.Decryption)
	assert.True(t, bc.Keys)
}

func TestKeyService_Coverage_ConvertRegistryCapabilities_Attestation(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapAttestation: true,
	}
	bc := convertRegistryCapabilities(caps)
	assert.True(t, bc.Attestation)
}

func TestKeyService_Coverage_ConvertRegistryCapabilities_Sealing(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSealing: true,
	}
	bc := convertRegistryCapabilities(caps)
	assert.True(t, bc.Sealing)
}

func TestKeyService_Coverage_ConvertRegistryCapabilities_DisabledCap(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.CapSigning: false,
	}
	bc := convertRegistryCapabilities(caps)
	assert.False(t, bc.Signing)
}

func TestKeyService_Coverage_ConvertRegistryCapabilities_UnknownCap(t *testing.T) {
	caps := map[backendregistry.Capability]bool{
		backendregistry.Capability("unknown"): true,
	}
	bc := convertRegistryCapabilities(caps)
	// Unknown capabilities are silently ignored.
	assert.False(t, bc.Signing)
	assert.False(t, bc.Attestation)
}

func TestKeyService_Coverage_ConvertRegistryCapabilities_Empty(t *testing.T) {
	bc := convertRegistryCapabilities(nil)
	assert.False(t, bc.Signing)
	assert.False(t, bc.Keys)
}

// ---------------------------------------------------------------------------
// ListRegisteredBackends tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ListRegisteredBackends_NilRegistry(t *testing.T) {
	svc := NewKeyService()
	result, err := svc.ListRegisteredBackends()
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoRegistry)
}

func TestKeyService_Coverage_ListRegisteredBackends_Empty(t *testing.T) {
	svc := NewKeyService()
	svc.SetRegistry(&mockRegistry{backends: []*backendregistry.RegisteredBackend{}})

	result, err := svc.ListRegisteredBackends()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestKeyService_Coverage_ListRegisteredBackends_FiltersCapsAndState(t *testing.T) {
	// Backend with signing capability, ready state -> included
	ready := &backendregistry.RegisteredBackend{
		ID:       "sw",
		Category: backendregistry.CategorySoftware,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning: true,
		},
	}
	ready.SetState(backendregistry.StateReady)

	// Backend with no signing/encryption -> excluded
	noCapBackend := &backendregistry.RegisteredBackend{
		ID:       "nocap",
		Category: backendregistry.CategorySoftware,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapOATH: true,
		},
	}
	noCapBackend.SetState(backendregistry.StateReady)

	// Backend in error state -> excluded
	errBackend := &backendregistry.RegisteredBackend{
		ID:       "err",
		Category: backendregistry.CategoryTPM2,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning: true,
		},
	}
	errBackend.SetState(backendregistry.StateError)

	// Backend in offline state -> excluded
	offlineBackend := &backendregistry.RegisteredBackend{
		ID:       "offline",
		Category: backendregistry.CategoryPKCS11,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapEncryption: true,
		},
	}
	offlineBackend.SetState(backendregistry.StateOffline)

	// Backend with encryption, ready state -> included
	encBackend := &backendregistry.RegisteredBackend{
		ID:       "enc",
		Category: backendregistry.CategoryTPM2,
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapEncryption: true,
		},
	}
	encBackend.SetState(backendregistry.StateReady)

	reg := &mockRegistry{
		backends: []*backendregistry.RegisteredBackend{ready, noCapBackend, errBackend, offlineBackend, encBackend},
	}
	svc := NewKeyService()
	svc.SetRegistry(reg)

	result, err := svc.ListRegisteredBackends()
	require.NoError(t, err)
	assert.Len(t, result, 2)

	ids := make(map[string]bool)
	for _, b := range result {
		ids[b.ID] = true
	}
	assert.True(t, ids["sw"])
	assert.True(t, ids["enc"])

	// Verify HardwareBacked flag - software is false, tpm2 is true.
	for _, b := range result {
		if b.ID == "sw" {
			assert.False(t, b.HardwareBacked)
		}
		if b.ID == "enc" {
			assert.True(t, b.HardwareBacked)
		}
	}
}

// ---------------------------------------------------------------------------
// convertBackendInfo tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ConvertBackendInfo_HardwareBacked(t *testing.T) {
	tests := []struct {
		name           string
		input          transport.BackendInfo
		expectHardware bool
	}{
		{
			name:           "HardwareBacked set directly",
			input:          transport.BackendInfo{ID: "a", HardwareBacked: true, Type: "software"},
			expectHardware: true,
		},
		{
			name:           "Capabilities.HardwareBacked",
			input:          transport.BackendInfo{ID: "b", Type: "software", Capabilities: transport.BackendCapabilities{HardwareBacked: true}},
			expectHardware: true,
		},
		{
			name:           "Type contains tpm2",
			input:          transport.BackendInfo{ID: "c", Type: "tpm2-default"},
			expectHardware: true,
		},
		{
			name:           "Type contains pkcs11",
			input:          transport.BackendInfo{ID: "d", Type: "PKCS11"},
			expectHardware: true,
		},
		{
			name:           "Type contains phone",
			input:          transport.BackendInfo{ID: "e", Type: "phone-backend"},
			expectHardware: true,
		},
		{
			name:           "Pure software",
			input:          transport.BackendInfo{ID: "f", Type: "software"},
			expectHardware: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := convertBackendInfo(&tc.input)
			assert.Equal(t, tc.input.ID, result.ID)
			assert.Equal(t, tc.input.Type, result.Type)
			assert.Equal(t, tc.expectHardware, result.HardwareBacked)
		})
	}
}

// ---------------------------------------------------------------------------
// convertKeyInfo test
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ConvertKeyInfo(t *testing.T) {
	ki := &transport.KeyInfo{
		KeyID:        "my-key",
		KeyType:      "SIGNING",
		Algorithm:    "ecdsa",
		Backend:      "software",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
	}
	result := convertKeyInfo(ki)
	assert.Equal(t, "my-key", result.KeyID)
	assert.Equal(t, "SIGNING", result.KeyType)
	assert.Equal(t, "ecdsa", result.Algorithm)
	assert.Equal(t, "software", result.Backend)
	assert.Contains(t, result.PublicKeyPEM, "PUBLIC KEY")
}

// ---------------------------------------------------------------------------
// GenerateKey validation tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_GenerateKey_NilParams(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("server", nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyInvalidRequest)
}

func TestKeyService_Coverage_GenerateKey_EmptyKeyID(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("server", &GenerateKeyParams{Backend: "sw"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyInvalidRequest)
}

func TestKeyService_Coverage_GenerateKey_EmptyBackend(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("server", &GenerateKeyParams{KeyID: "k1"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyInvalidRequest)
}

func TestKeyService_Coverage_GenerateKey_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.GenerateKey("server", &GenerateKeyParams{KeyID: "k1", Backend: "sw"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_GenerateKey_WithAuditLogger(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	al := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	mc := &mockClient{
		generateKeyFn: func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			return &transport.GenerateKeyResponse{KeyID: req.KeyID, KeyType: req.KeyType, Message: "ok"}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GenerateKey("local", &GenerateKeyParams{
		KeyID:   "k1",
		Backend: "sw",
		Purpose: "SIGNING",
	})
	require.NoError(t, err)
	assert.Equal(t, "k1", result.KeyID)
	assert.Equal(t, "ok", result.Message)
	assert.Len(t, al.entries, 1)
	assert.True(t, al.entries[0].Success)
}

func TestKeyService_Coverage_GenerateKey_PurposeFallback(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		generateKeyFn: func(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
			assert.Equal(t, "LEGACY_TYPE", req.KeyType)
			return &transport.GenerateKeyResponse{KeyID: req.KeyID, KeyType: req.KeyType}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GenerateKey("local", &GenerateKeyParams{
		KeyID:   "k2",
		Backend: "sw",
		KeyType: "LEGACY_TYPE",
	})
	require.NoError(t, err)
	assert.Equal(t, "LEGACY_TYPE", result.KeyType)
}

// ---------------------------------------------------------------------------
// ImportKey validation tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ImportKey_NilParams(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.ImportKey("server", nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyInvalidRequest)
}

func TestKeyService_Coverage_ImportKey_EmptyKeyID(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.ImportKey("server", &ImportKeyParams{Backend: "sw"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyInvalidRequest)
}

func TestKeyService_Coverage_ImportKey_EmptyBackend(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.ImportKey("server", &ImportKeyParams{KeyID: "k1"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyInvalidRequest)
}

func TestKeyService_Coverage_ImportKey_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.ImportKey("server", &ImportKeyParams{
		KeyID:   "k1",
		Backend: "sw",
		KeyData: base64.StdEncoding.EncodeToString([]byte("key-data")),
	})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_ImportKey_InvalidBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	result, err := svc.ImportKey("local", &ImportKeyParams{
		KeyID:   "k1",
		Backend: "sw",
		KeyData: "!!!not-base64!!!",
	})
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestKeyService_Coverage_ImportKey_Success(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	al := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	mc := &mockClient{
		importKeyFn: func(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
			return &transport.ImportKeyResponse{KeyID: req.KeyID, PublicKeyPEM: "PEM"}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.ImportKey("local", &ImportKeyParams{
		KeyID:   "k1",
		Backend: "sw",
		KeyData: base64.StdEncoding.EncodeToString([]byte("key-data")),
	})
	require.NoError(t, err)
	assert.Equal(t, "k1", result.KeyID)
	assert.Equal(t, "PEM", result.PublicKeyPEM)
	assert.Len(t, al.entries, 1)
}

// ---------------------------------------------------------------------------
// ExportKey tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ExportKey_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.ExportKey("server", "sw", "k1", "pkcs8")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_ExportKey_Success(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	al := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	mc := &mockClient{
		exportKeyFn: func(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
			return &transport.ExportKeyResponse{WrappedKeyMaterial: []byte("wrapped-key")}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.ExportKey("local", "sw", "k1", "pkcs8")
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(result)
	require.NoError(t, err)
	assert.Equal(t, "wrapped-key", string(decoded))
}

// ---------------------------------------------------------------------------
// RotateKey tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_RotateKey_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.RotateKey("server", "sw", "k1")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_RotateKey_Success(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	al := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	mc := &mockClient{
		rotateKeyFn: func(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
			return &transport.RotateKeyResponse{KeyID: req.KeyID, PublicKeyPEM: "rotated"}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.RotateKey("local", "sw", "k1")
	require.NoError(t, err)
	assert.Equal(t, "k1", result.KeyID)
	assert.Equal(t, "rotated", result.PublicKeyPEM)
}

// ---------------------------------------------------------------------------
// DeleteKey tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_DeleteKey_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	err := svc.DeleteKey("server", "sw", "k1")
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_DeleteKey_Success(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	al := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	mc := &mockClient{
		deleteKeyFn: func(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
			return &transport.DeleteKeyResponse{}, nil
		},
	}
	svc.SetLocalClient(mc)

	err := svc.DeleteKey("local", "sw", "k1")
	require.NoError(t, err)
	assert.Len(t, al.entries, 1)
}

// ---------------------------------------------------------------------------
// SignData tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_SignData_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.SignData("server", "sw", "k1", "sha256", base64.StdEncoding.EncodeToString([]byte("data")))
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_SignData_InvalidBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	result, err := svc.SignData("local", "sw", "k1", "sha256", "!!!invalid!!!")
	assert.Empty(t, result)
	assert.Error(t, err)
}

func TestKeyService_Coverage_SignData_Success(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		signFn: func(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
			return &transport.SignResponse{Signature: []byte("sig-bytes")}, nil
		},
	}
	svc.SetLocalClient(mc)

	data := base64.StdEncoding.EncodeToString([]byte("data"))
	result, err := svc.SignData("local", "sw", "k1", "sha256", data)
	require.NoError(t, err)
	decoded, err := base64.StdEncoding.DecodeString(result)
	require.NoError(t, err)
	assert.Equal(t, "sig-bytes", string(decoded))
}

// ---------------------------------------------------------------------------
// VerifySignature tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_VerifySignature_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	valid, err := svc.VerifySignature("server", "sw", "k1", "sha256",
		base64.StdEncoding.EncodeToString([]byte("data")),
		base64.StdEncoding.EncodeToString([]byte("sig")))
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_VerifySignature_InvalidDataBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	valid, err := svc.VerifySignature("local", "sw", "k1", "sha256", "!!!invalid!!!", "dGVzdA==")
	assert.False(t, valid)
	assert.Error(t, err)
}

func TestKeyService_Coverage_VerifySignature_InvalidSigBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	valid, err := svc.VerifySignature("local", "sw", "k1", "sha256",
		base64.StdEncoding.EncodeToString([]byte("data")), "!!!invalid!!!")
	assert.False(t, valid)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// EncryptData / DecryptData tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_EncryptData_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.EncryptData("server", "sw", "k1", "",
		base64.StdEncoding.EncodeToString([]byte("hello")))
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_EncryptData_InvalidBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	result, err := svc.EncryptData("local", "sw", "k1", "", "!!!invalid!!!")
	assert.Empty(t, result)
	assert.Error(t, err)
}

func TestKeyService_Coverage_DecryptData_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.DecryptData("server", "sw", "k1", "",
		base64.StdEncoding.EncodeToString([]byte("cipher")))
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_DecryptData_InvalidBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	result, err := svc.DecryptData("local", "sw", "k1", "", "!!!invalid!!!")
	assert.Empty(t, result)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// AttestKey tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_AttestKey_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.AttestKey("server", "sw", "k1", "")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_AttestKey_InvalidNonceBase64(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	mc := &mockClient{}
	svc.SetLocalClient(mc)

	result, err := svc.AttestKey("local", "sw", "k1", "!!!invalid!!!")
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestKeyService_Coverage_AttestKey_Success(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())
	al := &keyCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	mc := &mockClient{
		attestKeyFn: func(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
			return &transport.AttestKeyResponse{
				Format:           "tpm",
				CertificateChain: [][]byte{[]byte("cert1"), []byte("cert2")},
				AttestationData:  []byte("attest-data"),
				Signature:        []byte("sig-data"),
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.AttestKey("local", "sw", "k1", base64.StdEncoding.EncodeToString([]byte("nonce")))
	require.NoError(t, err)
	assert.Equal(t, "tpm", result.Format)
	assert.Len(t, result.CertificateChain, 2)
	assert.NotEmpty(t, result.AttestationData)
	assert.NotEmpty(t, result.Signature)
}

func TestKeyService_Coverage_AttestKey_EmptyNonce(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		attestKeyFn: func(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
			assert.Empty(t, req.Nonce)
			return &transport.AttestKeyResponse{Format: "none"}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.AttestKey("local", "sw", "k1", "")
	require.NoError(t, err)
	assert.Equal(t, "none", result.Format)
}

// ---------------------------------------------------------------------------
// BrowseFile / SaveFileAs nil context tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_BrowseFile_NilContext(t *testing.T) {
	svc := NewKeyService()
	// ctx is nil
	result, err := svc.BrowseFile()
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_SaveFileAs_NilContext(t *testing.T) {
	svc := NewKeyService()
	result, err := svc.SaveFileAs("test.key")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

// ---------------------------------------------------------------------------
// GetKeyCount tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_GetKeyCount_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	count := svc.GetKeyCount("server")
	assert.Equal(t, 0, count)
}

// ---------------------------------------------------------------------------
// File operations: EncryptFile, DecryptFile, SignFile, VerifyFileSignature
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_EncryptFile_ReadError(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	err := svc.EncryptFile("local", "sw", "k1", "/nonexistent/path", "/tmp/out", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestKeyService_Coverage_DecryptFile_ReadError(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	err := svc.DecryptFile("local", "sw", "k1", "/nonexistent/path", "/tmp/out", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestKeyService_Coverage_SignFile_ReadError(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	err := svc.SignFile("local", "sw", "k1", "sha256", "/nonexistent/path", "/tmp/out", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestKeyService_Coverage_VerifyFileSignature_DataReadError(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	valid, err := svc.VerifyFileSignature("local", "sw", "k1", "sha256",
		"/nonexistent/data", "/nonexistent/sig", "base64")
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestKeyService_Coverage_VerifyFileSignature_SigReadError(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "data.bin")
	require.NoError(t, os.WriteFile(dataFile, []byte("hello"), 0600))

	valid, err := svc.VerifyFileSignature("local", "sw", "k1", "sha256",
		dataFile, "/nonexistent/sig", "base64")
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

// ---------------------------------------------------------------------------
// GetSupportedKeyTypes tests
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_GetSupportedKeyTypes_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.GetSupportedKeyTypes("server", "sw")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestKeyService_Coverage_GetSupportedKeyTypes_Software(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "software",
				Capabilities: transport.BackendCapabilities{
					Signing:    true,
					Decryption: true,
				},
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GetSupportedKeyTypes("local", "sw")
	require.NoError(t, err)
	assert.Contains(t, result.Algorithms, "rsa")
	assert.Contains(t, result.Algorithms, "ecdsa")
	assert.Contains(t, result.Algorithms, "ed25519")
	assert.Contains(t, result.Algorithms, "aes")
	assert.Contains(t, result.Purposes, "SIGNING")
	assert.Contains(t, result.Purposes, "ENCRYPTION")
}

func TestKeyService_Coverage_GetSupportedKeyTypes_TPM2(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "tpm2",
				Capabilities: transport.BackendCapabilities{
					Signing:    true,
					Decryption: true,
				},
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GetSupportedKeyTypes("local", "tpm2-default")
	require.NoError(t, err)
	assert.Contains(t, result.Algorithms, "rsa")
	assert.Contains(t, result.Algorithms, "ecdsa")
	assert.NotContains(t, result.Algorithms, "ed25519")
	assert.Contains(t, result.Curves, "P-256")
	assert.Contains(t, result.Curves, "P-384")
	assert.NotContains(t, result.Curves, "P-521")
}

func TestKeyService_Coverage_GetSupportedKeyTypes_Phone(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "phone",
				Capabilities: transport.BackendCapabilities{
					Signing: true,
				},
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GetSupportedKeyTypes("local", "phone-default")
	require.NoError(t, err)
	assert.Contains(t, result.Algorithms, "ecdsa")
	assert.NotContains(t, result.Algorithms, "rsa")
	assert.Equal(t, []string{"P-256"}, result.Curves)
}

func TestKeyService_Coverage_GetSupportedKeyTypes_PKCS11(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "pkcs11",
				Capabilities: transport.BackendCapabilities{
					Signing: true,
				},
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GetSupportedKeyTypes("local", "pkcs11-default")
	require.NoError(t, err)
	assert.Contains(t, result.Algorithms, "rsa")
	assert.Contains(t, result.Algorithms, "ecdsa")
}

func TestKeyService_Coverage_GetSupportedKeyTypes_DefaultType(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "unknown-type",
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GetSupportedKeyTypes("local", "custom")
	require.NoError(t, err)
	assert.Contains(t, result.Algorithms, "rsa")
	assert.Contains(t, result.Algorithms, "ecdsa")
	assert.Contains(t, result.Algorithms, "ed25519")
	// No capabilities -> default purposes
	assert.Contains(t, result.Purposes, "SIGNING")
	assert.Contains(t, result.Purposes, "ENCRYPTION")
}

func TestKeyService_Coverage_GetSupportedKeyTypes_AllCapabilities(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	mc := &mockClient{
		getBackendFn: func(ctx context.Context, id string) (*transport.BackendInfo, error) {
			return &transport.BackendInfo{
				ID:   id,
				Type: "software",
				Capabilities: transport.BackendCapabilities{
					Signing:             true,
					Decryption:          true,
					KeyEncapsulation:    true,
					SymmetricEncryption: true,
					Attestation:         true,
					QuantumSigning:      true,
				},
			}, nil
		},
	}
	svc.SetLocalClient(mc)

	result, err := svc.GetSupportedKeyTypes("local", "sw")
	require.NoError(t, err)
	assert.Contains(t, result.Purposes, "SIGNING")
	assert.Contains(t, result.Purposes, "ENCRYPTION")
	assert.Contains(t, result.Purposes, "ENCAPSULATION")
	assert.Contains(t, result.Purposes, "SECRET")
	assert.Contains(t, result.Purposes, "HMAC")
	assert.Contains(t, result.Purposes, "ATTESTATION")
	assert.Contains(t, result.Algorithms, "ml-dsa-44")
	assert.Contains(t, result.Algorithms, "ml-kem-512")
}

// ---------------------------------------------------------------------------
// ListKeyProviders delegates to ListBackends
// ---------------------------------------------------------------------------

func TestKeyService_Coverage_ListKeyProviders_NoClient(t *testing.T) {
	svc := NewKeyService()
	svc.SetContext(context.Background())

	result, err := svc.ListKeyProviders("server")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}
