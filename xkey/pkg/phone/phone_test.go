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

package phone

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, types.BackendTypePhone, BackendTypePhone)
	assert.Equal(t, "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0", XKeyServiceUUIDString)
	assert.Equal(t, "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00001", ControlPointUUIDString)
	assert.Equal(t, "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00002", ResponseUUIDString)
	assert.Equal(t, "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00003", StatusUUIDString)
	assert.Equal(t, 247, DefaultMTU)
	assert.Equal(t, 23, MinMTU)
	assert.Equal(t, 30*time.Second, ScanTimeout)
	assert.Equal(t, 10*time.Second, ConnectTimeout)
	assert.Equal(t, 60*time.Second, OperationTimeout)
	assert.Equal(t, -7, COSEAlgES256)
	assert.Equal(t, -35, COSEAlgES384)
	assert.Equal(t, -36, COSEAlgES512)
}

func TestDefaultPhoneKeyBackendConfig(t *testing.T) {
	cfg := DefaultPhoneKeyBackendConfig()

	require.NotNil(t, cfg)
	assert.Equal(t, ScanTimeout, cfg.ScanTimeout)
	assert.Equal(t, ConnectTimeout, cfg.ConnectTimeout)
	assert.Equal(t, OperationTimeout, cfg.OperationTimeout)
	assert.Equal(t, DefaultMTU, cfg.MTU)
	assert.NotNil(t, cfg.Logger)
}

func TestPhoneKeyHandle(t *testing.T) {
	credID := []byte("test-credential-id")
	alg := COSEAlgES256

	handle := &phoneKeyHandle{
		credentialID: credID,
		algorithm:    alg,
	}

	assert.Equal(t, credID, handle.CredentialID())
	assert.Equal(t, alg, handle.Algorithm())
}

func TestPhoneKeyHandle_DifferentAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm int
	}{
		{"ES256", COSEAlgES256},
		{"ES384", COSEAlgES384},
		{"ES512", COSEAlgES512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := &phoneKeyHandle{
				credentialID: []byte("test"),
				algorithm:    tt.algorithm,
			}
			assert.Equal(t, tt.algorithm, handle.Algorithm())
		})
	}
}

func TestNewPhoneKeyBackend_NoBLE(t *testing.T) {
	cfg := DefaultPhoneKeyBackendConfig()

	backend, err := NewPhoneKeyBackend(cfg)

	// Without BLE build tag, should return ErrBLEUnavailable
	assert.Error(t, err)
	assert.Nil(t, backend)
	assert.ErrorIs(t, err, ErrBLEUnavailable)
}

func TestCapabilities(t *testing.T) {
	caps := keybackend.FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgES384, COSEAlgES512},
		SupportsExport:      false,
		SupportsImport:      false,
		SupportsAttestation: false,
		HardwareBacked:      true,
	}

	assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES256)
	assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES384)
	assert.Contains(t, caps.SupportedAlgorithms, COSEAlgES512)
	assert.False(t, caps.SupportsExport)
	assert.False(t, caps.SupportsImport)
	assert.False(t, caps.SupportsAttestation)
	assert.True(t, caps.HardwareBacked)
}

func TestIsAlgorithmSupported(t *testing.T) {
	supportedAlgs := []int{COSEAlgES256, COSEAlgES384, COSEAlgES512}

	isSupported := func(alg int) bool {
		for _, supported := range supportedAlgs {
			if alg == supported {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name      string
		algorithm int
		expected  bool
	}{
		{"ES256 supported", COSEAlgES256, true},
		{"ES384 supported", COSEAlgES384, true},
		{"ES512 supported", COSEAlgES512, true},
		{"EdDSA not supported", -8, false},
		{"RS256 not supported", -257, false},
		{"invalid algorithm", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isSupported(tt.algorithm))
		})
	}
}

func TestHandlesCaching(t *testing.T) {
	handles := make(map[string]*phoneKeyHandle)

	credID := []byte{0x01, 0x02, 0x03}
	handle := &phoneKeyHandle{
		credentialID: credID,
		algorithm:    COSEAlgES256,
	}
	handles[hex.EncodeToString(credID)] = handle

	retrieved, ok := handles[hex.EncodeToString(credID)]
	assert.True(t, ok)
	assert.Equal(t, handle, retrieved)

	delete(handles, hex.EncodeToString(credID))
	_, ok = handles[hex.EncodeToString(credID)]
	assert.False(t, ok)
}

func TestPhoneKeyBackendConfig_Validation(t *testing.T) {
	t.Run("valid config with device address", func(t *testing.T) {
		cfg := &PhoneKeyBackendConfig{
			DeviceAddress:    "AA:BB:CC:DD:EE:FF",
			ScanTimeout:      10 * time.Second,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 30 * time.Second,
			MTU:              247,
		}

		assert.NotEmpty(t, cfg.DeviceAddress)
		assert.Equal(t, 10*time.Second, cfg.ScanTimeout)
	})

	t.Run("valid config with expected remote key", func(t *testing.T) {
		key, err := GenerateStaticKey()
		require.NoError(t, err)

		cfg := &PhoneKeyBackendConfig{
			ExpectedRemoteStatic: key.Public,
			ScanTimeout:          ScanTimeout,
			ConnectTimeout:       ConnectTimeout,
			OperationTimeout:     OperationTimeout,
			MTU:                  DefaultMTU,
		}

		assert.NotEmpty(t, cfg.ExpectedRemoteStatic)
		assert.Len(t, cfg.ExpectedRemoteStatic, NoiseKeySize)
	})
}

func TestBLETransportConfig_Defaults(t *testing.T) {
	cfg := DefaultBLETransportConfig()

	require.NotNil(t, cfg)
	assert.Equal(t, ScanTimeout, cfg.ScanTimeout)
	assert.Equal(t, ConnectTimeout, cfg.ConnectTimeout)
	assert.Equal(t, OperationTimeout, cfg.OperationTimeout)
	assert.Equal(t, DefaultMTU, cfg.MTU)
	assert.NotNil(t, cfg.Logger)
}

func TestScanResult(t *testing.T) {
	result := ScanResult{
		Address:   "AA:BB:CC:DD:EE:FF",
		LocalName: "xKey Phone",
	}

	assert.Equal(t, "AA:BB:CC:DD:EE:FF", result.Address)
	assert.Equal(t, "xKey Phone", result.LocalName)
}

func TestErrorConditions(t *testing.T) {
	errors := []struct {
		name string
		err  error
	}{
		{"backend closed", ErrBackendClosed},
		{"not connected", ErrNotConnected},
		{"device not found", ErrDeviceNotFound},
		{"connection failed", ErrConnectionFailed},
		{"timeout", ErrTimeout},
		{"noise handshake failed", ErrNoiseHandshakeFailed},
		{"key not found", ErrKeyNotFound},
		{"user cancelled", ErrUserCancelled},
		{"biometric failed", ErrBiometricFailed},
		{"unsupported algorithm", ErrUnsupportedAlgorithm},
		{"export not supported", ErrExportNotSupported},
		{"import not supported", ErrImportNotSupported},
	}

	for _, tt := range errors {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err)
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}

func TestGetInfoResult(t *testing.T) {
	info := GetInfoResult{
		Version:             "1.0.0",
		DeviceName:          "Pixel 8 Pro",
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgES384},
		MaxCredentials:      100,
		CurrentCredentials:  5,
	}

	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "Pixel 8 Pro", info.DeviceName)
	assert.Len(t, info.SupportedAlgorithms, 2)
	assert.Equal(t, 100, info.MaxCredentials)
	assert.Equal(t, 5, info.CurrentCredentials)
}

func TestPingResult(t *testing.T) {
	result := PingResult{Pong: true}
	assert.True(t, result.Pong)

	result2 := PingResult{Pong: false}
	assert.False(t, result2.Pong)
}

func TestPhoneKeyBackend_LocalStaticPublicKey_NilSession(t *testing.T) {
	// Create backend with nil session (before connection)
	backend := &PhoneKeyBackend{
		session: nil,
	}

	result := backend.LocalStaticPublicKey()
	assert.Nil(t, result, "LocalStaticPublicKey should return nil when session is nil")
}

func TestPhoneKeyBackend_RemoteStaticPublicKey_NilSession(t *testing.T) {
	// Create backend with nil session (before connection)
	backend := &PhoneKeyBackend{
		session: nil,
	}

	result := backend.RemoteStaticPublicKey()
	assert.Nil(t, result, "RemoteStaticPublicKey should return nil when session is nil")
}

func TestPhoneKeyBackend_Notifier_Nil(t *testing.T) {
	backend := &PhoneKeyBackend{
		notifier: nil,
	}

	result := backend.Notifier()
	assert.Nil(t, result)
}

func TestPhoneKeyBackend_Notifier_Set(t *testing.T) {
	// Create a mock notifier for testing
	mockNotifier := &mockNotifierImpl{}
	backend := &PhoneKeyBackend{
		notifier: mockNotifier,
	}

	result := backend.Notifier()
	assert.NotNil(t, result)
	assert.Equal(t, mockNotifier, result)
}

// mockNotifierImpl is a simple mock for notify.Notifier
type mockNotifierImpl struct{}

func (m *mockNotifierImpl) NotifyTouchRequired(_ *notify.TouchRequest) error {
	return nil
}

func (m *mockNotifierImpl) Close() error {
	return nil
}

func BenchmarkPhoneKeyHandle_CredentialID(b *testing.B) {
	handle := &phoneKeyHandle{
		credentialID: make([]byte, 64),
		algorithm:    COSEAlgES256,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handle.CredentialID()
	}
}

func BenchmarkHexEncodeCredentialID(b *testing.B) {
	credID := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hex.EncodeToString(credID)
	}
}
