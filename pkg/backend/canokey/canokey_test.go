// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build pkcs11

package canokey

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				PIN:         "123456",
				KeyStorage:  &mockStorage{},
				CertStorage: &mockStorage{},
			},
			wantErr: false,
		},
		{
			name: "missing PIN",
			config: &Config{
				KeyStorage:  &mockStorage{},
				CertStorage: &mockStorage{},
			},
			wantErr: true,
		},
		{
			name: "PIN too short",
			config: &Config{
				PIN:         "12345",
				KeyStorage:  &mockStorage{},
				CertStorage: &mockStorage{},
			},
			wantErr: true,
		},
		{
			name: "PIN too long",
			config: &Config{
				PIN:         "123456789",
				KeyStorage:  &mockStorage{},
				CertStorage: &mockStorage{},
			},
			wantErr: true,
		},
		{
			name: "missing key storage",
			config: &Config{
				PIN:         "123456",
				CertStorage: &mockStorage{},
			},
			wantErr: true,
		},
		{
			name: "missing cert storage",
			config: &Config{
				PIN:        "123456",
				KeyStorage: &mockStorage{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	config := &Config{}
	config.SetDefaults()

	assert.Equal(t, DefaultPIN, config.PIN)
	assert.NotEmpty(t, config.Library)
}

func TestPIVSlot_String(t *testing.T) {
	tests := []struct {
		slot PIVSlot
		want string
	}{
		{SlotAuthentication, "PIV Authentication (9a)"},
		{SlotSignature, "Digital Signature (9c)"},
		{SlotKeyManagement, "Key Management (9d)"},
		{SlotCardAuth, "Card Authentication (9e)"},
		{SlotRetired1, "Retired Key Management 1 (82)"},
		{PIVSlot(0xFF), "Unknown Slot (ff)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.slot.String())
		})
	}
}

func TestPIVSlot_IsValid(t *testing.T) {
	tests := []struct {
		slot  PIVSlot
		valid bool
	}{
		{SlotAuthentication, true},
		{SlotSignature, true},
		{SlotKeyManagement, true},
		{SlotCardAuth, true},
		{SlotRetired1, true},
		{SlotRetired20, true},
		{PIVSlot(0xFF), false},
		{PIVSlot(0x00), false},
	}

	for _, tt := range tests {
		t.Run(tt.slot.String(), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.slot.IsValid())
		})
	}
}

func TestPIVSlot_RequiresPIN(t *testing.T) {
	tests := []struct {
		slot        PIVSlot
		requiresPIN bool
	}{
		{SlotAuthentication, true},
		{SlotSignature, true},
		{SlotKeyManagement, true},
		{SlotCardAuth, false}, // Card auth does not require PIN
		{SlotRetired1, true},
	}

	for _, tt := range tests {
		t.Run(tt.slot.String(), func(t *testing.T) {
			assert.Equal(t, tt.requiresPIN, tt.slot.RequiresPIN())
		})
	}
}

func TestPIVSlot_IsRetired(t *testing.T) {
	tests := []struct {
		slot      PIVSlot
		isRetired bool
	}{
		{SlotAuthentication, false},
		{SlotSignature, false},
		{SlotRetired1, true},
		{SlotRetired20, true},
		{PIVSlot(0x81), false}, // Just before retired range
		{PIVSlot(0x96), false}, // Just after retired range
	}

	for _, tt := range tests {
		t.Run(tt.slot.String(), func(t *testing.T) {
			assert.Equal(t, tt.isRetired, tt.slot.IsRetired())
		})
	}
}

func TestAllSlots(t *testing.T) {
	slots := AllSlots()
	assert.Len(t, slots, 24) // 4 primary + 20 retired

	// Verify all returned slots are valid
	for _, slot := range slots {
		assert.True(t, slot.IsValid())
	}
}

func TestPrimarySlots(t *testing.T) {
	slots := PrimarySlots()
	assert.Len(t, slots, 4)
	assert.Contains(t, slots, SlotAuthentication)
	assert.Contains(t, slots, SlotSignature)
	assert.Contains(t, slots, SlotKeyManagement)
	assert.Contains(t, slots, SlotCardAuth)
}

func TestRetiredSlots(t *testing.T) {
	slots := RetiredSlots()
	assert.Len(t, slots, 20)

	// Verify all are retired slots
	for _, slot := range slots {
		assert.True(t, slot.IsRetired())
	}
}

func TestParseSlot(t *testing.T) {
	tests := []struct {
		name    string
		b       byte
		want    PIVSlot
		wantErr bool
	}{
		{"authentication", 0x9a, SlotAuthentication, false},
		{"signature", 0x9c, SlotSignature, false},
		{"key management", 0x9d, SlotKeyManagement, false},
		{"card auth", 0x9e, SlotCardAuth, false},
		{"retired 1", 0x82, SlotRetired1, false},
		{"invalid", 0xFF, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSlot(tt.b)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestSlotFromKeyID(t *testing.T) {
	tests := []struct {
		name  string
		keyID []byte
		want  PIVSlot
	}{
		{"empty keyID", []byte{}, SlotAuthentication},
		{"authentication slot", []byte{0x9a}, SlotAuthentication},
		{"signature slot", []byte{0x9c}, SlotSignature},
		{"invalid slot", []byte{0xFF}, SlotAuthentication},
		{"multi-byte keyID", []byte{0x9d, 0x00, 0x01}, SlotKeyManagement},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlotFromKeyID(tt.keyID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFirmwareVersion_SupportsEd25519(t *testing.T) {
	tests := []struct {
		name     string
		version  *FirmwareVersion
		supports bool
	}{
		{"version 3.0.0", &FirmwareVersion{3, 0, 0}, true},
		{"version 3.1.0", &FirmwareVersion{3, 1, 0}, true},
		{"version 4.0.0", &FirmwareVersion{4, 0, 0}, true},
		{"version 2.0.0", &FirmwareVersion{2, 0, 0}, false},
		{"version 2.9.9", &FirmwareVersion{2, 9, 9}, false},
		{"nil version", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{firmwareVer: tt.version}
			assert.Equal(t, tt.supports, b.SupportsEd25519())
		})
	}
}

func TestFirmwareVersion_SupportsX25519(t *testing.T) {
	tests := []struct {
		name     string
		version  *FirmwareVersion
		supports bool
	}{
		{"version 3.0.0", &FirmwareVersion{3, 0, 0}, true},
		{"version 3.1.0", &FirmwareVersion{3, 1, 0}, true},
		{"version 4.0.0", &FirmwareVersion{4, 0, 0}, true},
		{"version 2.0.0", &FirmwareVersion{2, 0, 0}, false},
		{"version 2.9.9", &FirmwareVersion{2, 9, 9}, false},
		{"nil version", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{firmwareVer: tt.version}
			assert.Equal(t, tt.supports, b.SupportsX25519())
		})
	}
}

func TestBackend_Type(t *testing.T) {
	b := &Backend{}
	assert.Equal(t, "canokey", string(b.Type()))
}

func TestBackend_Capabilities(t *testing.T) {
	t.Run("hardware mode", func(t *testing.T) {
		b := &Backend{
			config: &Config{IsVirtual: false},
		}
		caps := b.Capabilities()
		assert.True(t, caps.Keys)
		assert.True(t, caps.HardwareBacked)
		assert.True(t, caps.Signing)
		assert.True(t, caps.Decryption)
		assert.True(t, caps.SymmetricEncryption)
		assert.True(t, caps.Sealing)
		assert.False(t, caps.Import) // PIV keys non-exportable
		assert.False(t, caps.Export) // PIV keys non-exportable
	})

	t.Run("virtual mode (QEMU)", func(t *testing.T) {
		b := &Backend{
			config: &Config{IsVirtual: true},
		}
		caps := b.Capabilities()
		assert.True(t, caps.Keys)
		assert.False(t, caps.HardwareBacked) // Virtual mode
		assert.True(t, caps.Signing)
		assert.True(t, caps.Decryption)
		assert.True(t, caps.SymmetricEncryption)
		assert.True(t, caps.Sealing)
		assert.False(t, caps.Import)
		assert.False(t, caps.Export)
	})
}

// mockStorage is a mock implementation of storage.Backend for testing
type mockStorage struct{}

func (m *mockStorage) Get(key string) ([]byte, error)                            { return nil, nil }
func (m *mockStorage) Put(key string, value []byte, opts *storage.Options) error { return nil }
func (m *mockStorage) Delete(key string) error                                   { return nil }
func (m *mockStorage) Exists(key string) (bool, error)                           { return false, nil }
func (m *mockStorage) List(prefix string) ([]string, error)                      { return nil, nil }
func (m *mockStorage) Close() error                                              { return nil }
