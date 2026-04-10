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

package pivcert

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func TestPIVStorageType_IsValid(t *testing.T) {
	tests := []struct {
		name        string
		storageType PIVStorageType
		want        bool
	}{
		{
			name:        "valid file storage type",
			storageType: StorageTypeFile,
			want:        true,
		},
		{
			name:        "valid tpm2 storage type",
			storageType: StorageTypeTPM2,
			want:        true,
		},
		{
			name:        "valid pkcs11 storage type",
			storageType: StorageTypePKCS11,
			want:        true,
		},
		{
			name:        "invalid empty storage type",
			storageType: PIVStorageType(""),
			want:        false,
		},
		{
			name:        "invalid unknown storage type",
			storageType: PIVStorageType("unknown"),
			want:        false,
		},
		{
			name:        "invalid case sensitive - FILE",
			storageType: PIVStorageType("FILE"),
			want:        false,
		},
		{
			name:        "invalid whitespace",
			storageType: PIVStorageType(" file "),
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.storageType.IsValid()
			if got != tt.want {
				t.Errorf("PIVStorageType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIVStorageType_String(t *testing.T) {
	tests := []struct {
		name        string
		storageType PIVStorageType
		want        string
	}{
		{
			name:        "file storage type string",
			storageType: StorageTypeFile,
			want:        "file",
		},
		{
			name:        "tpm2 storage type string",
			storageType: StorageTypeTPM2,
			want:        "tpm2",
		},
		{
			name:        "pkcs11 storage type string",
			storageType: StorageTypePKCS11,
			want:        "pkcs11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.storageType.String()
			if got != tt.want {
				t.Errorf("PIVStorageType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIVSlot_IsValid(t *testing.T) {
	tests := []struct {
		name string
		slot PIVSlot
		want bool
	}{
		// Primary slots
		{
			name: "valid authentication slot 9a",
			slot: PIVSlotAuthentication,
			want: true,
		},
		{
			name: "valid digital signature slot 9c",
			slot: PIVSlotDigitalSignature,
			want: true,
		},
		{
			name: "valid key management slot 9d",
			slot: PIVSlotKeyManagement,
			want: true,
		},
		{
			name: "valid card authentication slot 9e",
			slot: PIVSlotCardAuthentication,
			want: true,
		},
		{
			name: "valid attestation slot f9",
			slot: PIVSlotAttestation,
			want: true,
		},
		// Retired slots
		{
			name: "valid retired slot 1 (82)",
			slot: PIVSlotRetired1,
			want: true,
		},
		{
			name: "valid retired slot 10 (8b)",
			slot: PIVSlotRetired10,
			want: true,
		},
		{
			name: "valid retired slot 20 (95)",
			slot: PIVSlotRetired20,
			want: true,
		},
		// Invalid slots
		{
			name: "invalid empty slot",
			slot: PIVSlot(""),
			want: false,
		},
		{
			name: "invalid unknown slot",
			slot: PIVSlot("99"),
			want: false,
		},
		{
			name: "invalid case sensitive slot",
			slot: PIVSlot("9A"),
			want: false,
		},
		{
			name: "invalid hex slot",
			slot: PIVSlot("0x9a"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slot.IsValid()
			if got != tt.want {
				t.Errorf("PIVSlot.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIVSlot_IsPrimarySlot(t *testing.T) {
	tests := []struct {
		name string
		slot PIVSlot
		want bool
	}{
		{
			name: "authentication is primary",
			slot: PIVSlotAuthentication,
			want: true,
		},
		{
			name: "digital signature is primary",
			slot: PIVSlotDigitalSignature,
			want: true,
		},
		{
			name: "key management is primary",
			slot: PIVSlotKeyManagement,
			want: true,
		},
		{
			name: "card authentication is primary",
			slot: PIVSlotCardAuthentication,
			want: true,
		},
		{
			name: "retired slot 1 is not primary",
			slot: PIVSlotRetired1,
			want: false,
		},
		{
			name: "retired slot 20 is not primary",
			slot: PIVSlotRetired20,
			want: false,
		},
		{
			name: "attestation slot is not primary",
			slot: PIVSlotAttestation,
			want: false,
		},
		{
			name: "invalid slot is not primary",
			slot: PIVSlot("invalid"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slot.IsPrimarySlot()
			if got != tt.want {
				t.Errorf("PIVSlot.IsPrimarySlot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIVSlot_IsRetiredSlot(t *testing.T) {
	tests := []struct {
		name string
		slot PIVSlot
		want bool
	}{
		{
			name: "authentication is not retired",
			slot: PIVSlotAuthentication,
			want: false,
		},
		{
			name: "retired slot 1 is retired",
			slot: PIVSlotRetired1,
			want: true,
		},
		{
			name: "retired slot 10 is retired",
			slot: PIVSlotRetired10,
			want: true,
		},
		{
			name: "retired slot 20 is retired",
			slot: PIVSlotRetired20,
			want: true,
		},
		{
			name: "attestation slot is not retired",
			slot: PIVSlotAttestation,
			want: false,
		},
		{
			name: "invalid slot is not retired",
			slot: PIVSlot("invalid"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slot.IsRetiredSlot()
			if got != tt.want {
				t.Errorf("PIVSlot.IsRetiredSlot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIVSlot_IsAttestationSlot(t *testing.T) {
	tests := []struct {
		name string
		slot PIVSlot
		want bool
	}{
		{
			name: "attestation slot is attestation",
			slot: PIVSlotAttestation,
			want: true,
		},
		{
			name: "authentication slot is not attestation",
			slot: PIVSlotAuthentication,
			want: false,
		},
		{
			name: "retired slot is not attestation",
			slot: PIVSlotRetired1,
			want: false,
		},
		{
			name: "invalid slot is not attestation",
			slot: PIVSlot("invalid"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slot.IsAttestationSlot()
			if got != tt.want {
				t.Errorf("PIVSlot.IsAttestationSlot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIVSlot_String(t *testing.T) {
	tests := []struct {
		name string
		slot PIVSlot
		want string
	}{
		{
			name: "authentication slot string",
			slot: PIVSlotAuthentication,
			want: "9a",
		},
		{
			name: "retired slot 10 string",
			slot: PIVSlotRetired10,
			want: "8b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slot.String()
			if got != tt.want {
				t.Errorf("PIVSlot.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSlot(t *testing.T) {
	tests := []struct {
		name    string
		slot    PIVSlot
		wantErr error
	}{
		{
			name:    "valid authentication slot",
			slot:    PIVSlotAuthentication,
			wantErr: nil,
		},
		{
			name:    "valid digital signature slot",
			slot:    PIVSlotDigitalSignature,
			wantErr: nil,
		},
		{
			name:    "valid retired slot",
			slot:    PIVSlotRetired15,
			wantErr: nil,
		},
		{
			name:    "valid attestation slot",
			slot:    PIVSlotAttestation,
			wantErr: nil,
		},
		{
			name:    "invalid empty slot",
			slot:    PIVSlot(""),
			wantErr: ErrInvalidSlot,
		},
		{
			name:    "invalid unknown slot",
			slot:    PIVSlot("ff"),
			wantErr: ErrInvalidSlot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSlot(tt.slot)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateSlot() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateSlot() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestParseSlot(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    PIVSlot
		wantErr error
	}{
		{
			name:    "parse authentication slot",
			input:   "9a",
			want:    PIVSlotAuthentication,
			wantErr: nil,
		},
		{
			name:    "parse digital signature slot",
			input:   "9c",
			want:    PIVSlotDigitalSignature,
			wantErr: nil,
		},
		{
			name:    "parse key management slot",
			input:   "9d",
			want:    PIVSlotKeyManagement,
			wantErr: nil,
		},
		{
			name:    "parse card authentication slot",
			input:   "9e",
			want:    PIVSlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "parse attestation slot",
			input:   "f9",
			want:    PIVSlotAttestation,
			wantErr: nil,
		},
		{
			name:    "parse retired slot 1",
			input:   "82",
			want:    PIVSlotRetired1,
			wantErr: nil,
		},
		{
			name:    "parse retired slot 20",
			input:   "95",
			want:    PIVSlotRetired20,
			wantErr: nil,
		},
		{
			name:    "parse invalid empty string",
			input:   "",
			want:    "",
			wantErr: ErrInvalidSlot,
		},
		{
			name:    "parse invalid slot",
			input:   "invalid",
			want:    "",
			wantErr: ErrInvalidSlot,
		},
		{
			name:    "parse invalid uppercase",
			input:   "9A",
			want:    "",
			wantErr: ErrInvalidSlot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSlot(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ParseSlot() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSlot() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSlot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrimarySlots(t *testing.T) {
	slots := PrimarySlots()

	if len(slots) != 4 {
		t.Errorf("PrimarySlots() returned %d slots, want 4", len(slots))
	}

	expectedSlots := []PIVSlot{
		PIVSlotAuthentication,
		PIVSlotDigitalSignature,
		PIVSlotKeyManagement,
		PIVSlotCardAuthentication,
	}

	for i, expected := range expectedSlots {
		if slots[i] != expected {
			t.Errorf("PrimarySlots()[%d] = %v, want %v", i, slots[i], expected)
		}
	}

	// Verify all returned slots are primary
	for _, slot := range slots {
		if !slot.IsPrimarySlot() {
			t.Errorf("PrimarySlots() returned non-primary slot: %v", slot)
		}
	}
}

func TestRetiredSlots(t *testing.T) {
	slots := RetiredSlots()

	if len(slots) != 20 {
		t.Errorf("RetiredSlots() returned %d slots, want 20", len(slots))
	}

	// Verify all returned slots are retired
	for _, slot := range slots {
		if !slot.IsRetiredSlot() {
			t.Errorf("RetiredSlots() returned non-retired slot: %v", slot)
		}
	}

	// Verify first and last
	if slots[0] != PIVSlotRetired1 {
		t.Errorf("RetiredSlots()[0] = %v, want %v", slots[0], PIVSlotRetired1)
	}
	if slots[19] != PIVSlotRetired20 {
		t.Errorf("RetiredSlots()[19] = %v, want %v", slots[19], PIVSlotRetired20)
	}
}

func TestAllSlots(t *testing.T) {
	slots := AllSlots()

	// 4 primary + 1 attestation + 20 retired = 25 total
	if len(slots) != 25 {
		t.Errorf("AllSlots() returned %d slots, want 25", len(slots))
	}

	// Verify all slots are valid
	for _, slot := range slots {
		if !slot.IsValid() {
			t.Errorf("AllSlots() returned invalid slot: %v", slot)
		}
	}
}

func TestSlotName(t *testing.T) {
	// Test all slots to ensure complete coverage of the switch statement
	tests := []struct {
		name string
		slot PIVSlot
		want string
	}{
		// Primary slots
		{
			name: "authentication slot name",
			slot: PIVSlotAuthentication,
			want: "PIV Authentication",
		},
		{
			name: "digital signature slot name",
			slot: PIVSlotDigitalSignature,
			want: "Digital Signature",
		},
		{
			name: "key management slot name",
			slot: PIVSlotKeyManagement,
			want: "Key Management",
		},
		{
			name: "card authentication slot name",
			slot: PIVSlotCardAuthentication,
			want: "Card Authentication",
		},
		{
			name: "attestation slot name",
			slot: PIVSlotAttestation,
			want: "Attestation",
		},
		// All retired slots to ensure full coverage
		{name: "retired slot 1 name", slot: PIVSlotRetired1, want: "Retired Key 1"},
		{name: "retired slot 2 name", slot: PIVSlotRetired2, want: "Retired Key 2"},
		{name: "retired slot 3 name", slot: PIVSlotRetired3, want: "Retired Key 3"},
		{name: "retired slot 4 name", slot: PIVSlotRetired4, want: "Retired Key 4"},
		{name: "retired slot 5 name", slot: PIVSlotRetired5, want: "Retired Key 5"},
		{name: "retired slot 6 name", slot: PIVSlotRetired6, want: "Retired Key 6"},
		{name: "retired slot 7 name", slot: PIVSlotRetired7, want: "Retired Key 7"},
		{name: "retired slot 8 name", slot: PIVSlotRetired8, want: "Retired Key 8"},
		{name: "retired slot 9 name", slot: PIVSlotRetired9, want: "Retired Key 9"},
		{name: "retired slot 10 name", slot: PIVSlotRetired10, want: "Retired Key 10"},
		{name: "retired slot 11 name", slot: PIVSlotRetired11, want: "Retired Key 11"},
		{name: "retired slot 12 name", slot: PIVSlotRetired12, want: "Retired Key 12"},
		{name: "retired slot 13 name", slot: PIVSlotRetired13, want: "Retired Key 13"},
		{name: "retired slot 14 name", slot: PIVSlotRetired14, want: "Retired Key 14"},
		{name: "retired slot 15 name", slot: PIVSlotRetired15, want: "Retired Key 15"},
		{name: "retired slot 16 name", slot: PIVSlotRetired16, want: "Retired Key 16"},
		{name: "retired slot 17 name", slot: PIVSlotRetired17, want: "Retired Key 17"},
		{name: "retired slot 18 name", slot: PIVSlotRetired18, want: "Retired Key 18"},
		{name: "retired slot 19 name", slot: PIVSlotRetired19, want: "Retired Key 19"},
		{name: "retired slot 20 name", slot: PIVSlotRetired20, want: "Retired Key 20"},
		{
			name: "unknown slot name",
			slot: PIVSlot("unknown"),
			want: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlotName(tt.slot)
			if got != tt.want {
				t.Errorf("SlotName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSlotDescription(t *testing.T) {
	tests := []struct {
		name     string
		slot     PIVSlot
		contains string
	}{
		{
			name:     "authentication slot description",
			slot:     PIVSlotAuthentication,
			contains: "PIV card and cardholder authentication",
		},
		{
			name:     "digital signature slot description",
			slot:     PIVSlotDigitalSignature,
			contains: "document signing",
		},
		{
			name:     "key management slot description",
			slot:     PIVSlotKeyManagement,
			contains: "key establishment",
		},
		{
			name:     "card authentication slot description",
			slot:     PIVSlotCardAuthentication,
			contains: "card authentication without cardholder interaction",
		},
		{
			name:     "attestation slot description",
			slot:     PIVSlotAttestation,
			contains: "attestation certificate",
		},
		{
			name:     "retired slot description",
			slot:     PIVSlotRetired1,
			contains: "Historical key management",
		},
		{
			name:     "unknown slot description",
			slot:     PIVSlot("unknown"),
			contains: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlotDescription(tt.slot)
			if got == "" {
				t.Error("SlotDescription() returned empty string")
			}
			// Check description contains expected text
			if tt.contains != "" && !containsString(got, tt.contains) {
				t.Errorf("SlotDescription() = %q, expected to contain %q", got, tt.contains)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestNewStorageError(t *testing.T) {
	tests := []struct {
		name string
		op   string
		slot PIVSlot
		err  error
	}{
		{
			name: "storage error with slot",
			op:   "Store",
			slot: PIVSlotAuthentication,
			err:  ErrInvalidCertificate,
		},
		{
			name: "storage error without slot",
			op:   "List",
			slot: "",
			err:  ErrStorageClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewStorageError(tt.op, tt.slot, tt.err)
			if err == nil {
				t.Fatal("NewStorageError() returned nil")
			}
			if err.Op != tt.op {
				t.Errorf("NewStorageError().Op = %v, want %v", err.Op, tt.op)
			}
			if err.Slot != tt.slot {
				t.Errorf("NewStorageError().Slot = %v, want %v", err.Slot, tt.slot)
			}
			if err.Err != tt.err {
				t.Errorf("NewStorageError().Err = %v, want %v", err.Err, tt.err)
			}
		})
	}
}

func TestNewStorageTypeError(t *testing.T) {
	err := NewStorageTypeError("Init", StorageTypeTPM2, ErrTPMNotAvailable)
	if err == nil {
		t.Fatal("NewStorageTypeError() returned nil")
	}
	if err.Op != "Init" {
		t.Errorf("NewStorageTypeError().Op = %v, want Init", err.Op)
	}
	if err.StorageType != StorageTypeTPM2 {
		t.Errorf("NewStorageTypeError().StorageType = %v, want %v", err.StorageType, StorageTypeTPM2)
	}
	if err.Err != ErrTPMNotAvailable {
		t.Errorf("NewStorageTypeError().Err = %v, want %v", err.Err, ErrTPMNotAvailable)
	}
}

func TestPIVStorageError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *PIVStorageError
		contains []string
	}{
		{
			name: "error with slot",
			err: &PIVStorageError{
				Op:   "Store",
				Slot: PIVSlotAuthentication,
				Err:  ErrInvalidCertificate,
			},
			contains: []string{"pivcert:", "Store", "9a", "invalid certificate"},
		},
		{
			name: "error with storage type",
			err: &PIVStorageError{
				Op:          "Init",
				StorageType: StorageTypeTPM2,
				Err:         ErrTPMNotAvailable,
			},
			contains: []string{"pivcert:", "Init", "tpm2", "TPM not available"},
		},
		{
			name: "error without slot or storage type",
			err: &PIVStorageError{
				Op:  "validate",
				Err: ErrInvalidConfig,
			},
			contains: []string{"pivcert:", "validate", "invalid configuration"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, substr := range tt.contains {
				if !containsString(errStr, substr) {
					t.Errorf("PIVStorageError.Error() = %q, expected to contain %q", errStr, substr)
				}
			}
		})
	}
}

func TestPIVStorageError_Unwrap(t *testing.T) {
	underlying := ErrCertificateNotFound
	err := &PIVStorageError{
		Op:   "Retrieve",
		Slot: PIVSlotAuthentication,
		Err:  underlying,
	}

	unwrapped := err.Unwrap()
	if unwrapped != underlying {
		t.Errorf("PIVStorageError.Unwrap() = %v, want %v", unwrapped, underlying)
	}

	// Test with errors.Is
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Error("errors.Is() should return true for wrapped error")
	}

	// Test with errors.As
	var storageErr *PIVStorageError
	if !errors.As(err, &storageErr) {
		t.Error("errors.As() should succeed for PIVStorageError")
	}
}

func TestPIVStorageError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    *PIVStorageError
		target error
		want   bool
	}{
		{
			name: "matches underlying error",
			err: &PIVStorageError{
				Op:  "Store",
				Err: ErrInvalidCertificate,
			},
			target: ErrInvalidCertificate,
			want:   true,
		},
		{
			name: "does not match different error",
			err: &PIVStorageError{
				Op:  "Store",
				Err: ErrInvalidCertificate,
			},
			target: ErrCertificateNotFound,
			want:   false,
		},
		{
			name: "does not match nil",
			err: &PIVStorageError{
				Op:  "Store",
				Err: ErrInvalidCertificate,
			},
			target: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Is(tt.target)
			if got != tt.want {
				t.Errorf("PIVStorageError.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileStorageConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *FileStorageConfig
		wantErr error
	}{
		{
			name: "valid config with both formats",
			config: &FileStorageConfig{
				Backend:    storage.NewMemory(),
				DEREnabled: true,
				PEMEnabled: true,
			},
			wantErr: nil,
		},
		{
			name: "valid config with DER only",
			config: &FileStorageConfig{
				Backend:    storage.NewMemory(),
				DEREnabled: true,
				PEMEnabled: false,
			},
			wantErr: nil,
		},
		{
			name: "valid config with PEM only",
			config: &FileStorageConfig{
				Backend:    storage.NewMemory(),
				DEREnabled: false,
				PEMEnabled: true,
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrInvalidConfig,
		},
		{
			name: "empty base path",
			config: &FileStorageConfig{
				Backend:    nil,
				DEREnabled: true,
				PEMEnabled: true,
			},
			wantErr: ErrMissingBackend,
		},
		{
			name: "no format enabled",
			config: &FileStorageConfig{
				Backend:    storage.NewMemory(),
				DEREnabled: false,
				PEMEnabled: false,
			},
			wantErr: ErrNoFormatEnabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("FileStorageConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("FileStorageConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("FileStorageConfig.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestTPM2StorageConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *TPM2StorageConfig
		wantErr error
	}{
		{
			name: "valid config",
			config: &TPM2StorageConfig{
				DevicePath: "/dev/tpmrm0",
				BaseIndex:  DefaultTPM2BaseIndex,
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrInvalidConfig,
		},
		{
			name: "missing device path",
			config: &TPM2StorageConfig{
				DevicePath: "",
				BaseIndex:  DefaultTPM2BaseIndex,
			},
			wantErr: ErrMissingDevicePath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("TPM2StorageConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("TPM2StorageConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("TPM2StorageConfig.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestPKCS11StorageConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *PKCS11StorageConfig
		wantErr error
	}{
		{
			name: "valid config",
			config: &PKCS11StorageConfig{
				LibraryPath: "/usr/lib/libsofthsm2.so",
				TokenLabel:  "test-token",
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrInvalidConfig,
		},
		{
			name: "missing library path",
			config: &PKCS11StorageConfig{
				LibraryPath: "",
				TokenLabel:  "test-token",
			},
			wantErr: ErrMissingLibraryPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("PKCS11StorageConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("PKCS11StorageConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("PKCS11StorageConfig.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestPIVConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *PIVConfig
		wantErr error
	}{
		{
			name: "valid file config",
			config: &PIVConfig{
				StorageType: StorageTypeFile,
				FileConfig: &FileStorageConfig{
					Backend:    storage.NewMemory(),
					DEREnabled: true,
				},
			},
			wantErr: nil,
		},
		{
			name: "valid tpm2 config",
			config: &PIVConfig{
				StorageType: StorageTypeTPM2,
				TPM2Config: &TPM2StorageConfig{
					DevicePath: "/dev/tpmrm0",
				},
			},
			wantErr: nil,
		},
		{
			name: "valid pkcs11 config",
			config: &PIVConfig{
				StorageType: StorageTypePKCS11,
				PKCS11Config: &PKCS11StorageConfig{
					LibraryPath: "/usr/lib/libsofthsm2.so",
				},
			},
			wantErr: nil,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrInvalidConfig,
		},
		{
			name: "invalid storage type",
			config: &PIVConfig{
				StorageType: PIVStorageType("invalid"),
			},
			wantErr: ErrInvalidStorageType,
		},
		{
			name: "file type without file config",
			config: &PIVConfig{
				StorageType: StorageTypeFile,
			},
			wantErr: ErrMissingConfig,
		},
		{
			name: "tpm2 type without tpm2 config",
			config: &PIVConfig{
				StorageType: StorageTypeTPM2,
			},
			wantErr: ErrMissingConfig,
		},
		{
			name: "pkcs11 type without pkcs11 config",
			config: &PIVConfig{
				StorageType: StorageTypePKCS11,
			},
			wantErr: ErrMissingConfig,
		},
		{
			name: "file config validation error",
			config: &PIVConfig{
				StorageType: StorageTypeFile,
				FileConfig: &FileStorageConfig{
					Backend: nil, // Invalid: empty
				},
			},
			wantErr: ErrMissingBackend,
		},
		{
			name: "tpm2 config validation error",
			config: &PIVConfig{
				StorageType: StorageTypeTPM2,
				TPM2Config: &TPM2StorageConfig{
					DevicePath: "", // Invalid: empty
				},
			},
			wantErr: ErrMissingDevicePath,
		},
		{
			name: "pkcs11 config validation error",
			config: &PIVConfig{
				StorageType: StorageTypePKCS11,
				PKCS11Config: &PKCS11StorageConfig{
					LibraryPath: "", // Invalid: empty
				},
			},
			wantErr: ErrMissingLibraryPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("PIVConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("PIVConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("PIVConfig.Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestCertFormat_String(t *testing.T) {
	tests := []struct {
		name   string
		format CertFormat
		want   string
	}{
		{
			name:   "DER format string",
			format: FormatDER,
			want:   "DER",
		},
		{
			name:   "PEM format string",
			format: FormatPEM,
			want:   "PEM",
		},
		{
			name:   "unknown format string",
			format: CertFormat(99),
			want:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.format.String()
			if got != tt.want {
				t.Errorf("CertFormat.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertFormat_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		format CertFormat
		want   bool
	}{
		{
			name:   "DER is valid",
			format: FormatDER,
			want:   true,
		},
		{
			name:   "PEM is valid",
			format: FormatPEM,
			want:   true,
		},
		{
			name:   "invalid format",
			format: CertFormat(99),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.format.IsValid()
			if got != tt.want {
				t.Errorf("CertFormat.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetNVIndex(t *testing.T) {
	tests := []struct {
		name      string
		slot      PIVSlot
		baseIndex uint32
		want      uint32
		wantErr   error
	}{
		{
			name:      "authentication slot",
			slot:      PIVSlotAuthentication,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x00,
			wantErr:   nil,
		},
		{
			name:      "digital signature slot",
			slot:      PIVSlotDigitalSignature,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x01,
			wantErr:   nil,
		},
		{
			name:      "key management slot",
			slot:      PIVSlotKeyManagement,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x02,
			wantErr:   nil,
		},
		{
			name:      "card authentication slot",
			slot:      PIVSlotCardAuthentication,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x03,
			wantErr:   nil,
		},
		{
			name:      "attestation slot",
			slot:      PIVSlotAttestation,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x04,
			wantErr:   nil,
		},
		{
			name:      "retired slot 1",
			slot:      PIVSlotRetired1,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x10,
			wantErr:   nil,
		},
		{
			name:      "retired slot 20",
			slot:      PIVSlotRetired20,
			baseIndex: DefaultTPM2BaseIndex,
			want:      DefaultTPM2BaseIndex + 0x23,
			wantErr:   nil,
		},
		{
			name:      "invalid slot",
			slot:      PIVSlot("invalid"),
			baseIndex: DefaultTPM2BaseIndex,
			want:      0,
			wantErr:   ErrInvalidSlot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetNVIndex(tt.slot, tt.baseIndex)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetNVIndex() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("GetNVIndex() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("GetNVIndex() = 0x%x, want 0x%x", got, tt.want)
			}
		})
	}
}

func TestDefaultSlotMetadata(t *testing.T) {
	tests := []struct {
		name               string
		slot               PIVSlot
		wantErr            error
		wantName           string
		wantRequiresPIN    bool
		wantKeyUsage       x509.KeyUsage
		wantExtKeyUsageLen int
	}{
		{
			name:               "authentication slot metadata",
			slot:               PIVSlotAuthentication,
			wantErr:            nil,
			wantName:           "PIV Authentication",
			wantRequiresPIN:    true,
			wantKeyUsage:       x509.KeyUsageDigitalSignature,
			wantExtKeyUsageLen: 1,
		},
		{
			name:               "digital signature slot metadata",
			slot:               PIVSlotDigitalSignature,
			wantErr:            nil,
			wantName:           "Digital Signature",
			wantRequiresPIN:    true,
			wantKeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			wantExtKeyUsageLen: 1,
		},
		{
			name:               "key management slot metadata",
			slot:               PIVSlotKeyManagement,
			wantErr:            nil,
			wantName:           "Key Management",
			wantRequiresPIN:    true,
			wantKeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
			wantExtKeyUsageLen: 1,
		},
		{
			name:               "card authentication slot metadata",
			slot:               PIVSlotCardAuthentication,
			wantErr:            nil,
			wantName:           "Card Authentication",
			wantRequiresPIN:    false,
			wantKeyUsage:       x509.KeyUsageDigitalSignature,
			wantExtKeyUsageLen: 1,
		},
		{
			name:               "attestation slot metadata",
			slot:               PIVSlotAttestation,
			wantErr:            nil,
			wantName:           "Attestation",
			wantRequiresPIN:    false,
			wantKeyUsage:       x509.KeyUsageDigitalSignature,
			wantExtKeyUsageLen: 0,
		},
		{
			name:               "retired slot metadata",
			slot:               PIVSlotRetired1,
			wantErr:            nil,
			wantName:           "Retired Key 1",
			wantRequiresPIN:    true,
			wantKeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
			wantExtKeyUsageLen: 1,
		},
		{
			name:    "invalid slot",
			slot:    PIVSlot("invalid"),
			wantErr: ErrInvalidSlot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, err := DefaultSlotMetadata(tt.slot)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("DefaultSlotMetadata() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("DefaultSlotMetadata() unexpected error = %v", err)
				return
			}
			if meta == nil {
				t.Fatal("DefaultSlotMetadata() returned nil metadata")
			}
			if meta.Name != tt.wantName {
				t.Errorf("DefaultSlotMetadata().Name = %v, want %v", meta.Name, tt.wantName)
			}
			if meta.RequiresPIN != tt.wantRequiresPIN {
				t.Errorf("DefaultSlotMetadata().RequiresPIN = %v, want %v", meta.RequiresPIN, tt.wantRequiresPIN)
			}
			if meta.KeyUsage != tt.wantKeyUsage {
				t.Errorf("DefaultSlotMetadata().KeyUsage = %v, want %v", meta.KeyUsage, tt.wantKeyUsage)
			}
			if len(meta.ExtKeyUsage) != tt.wantExtKeyUsageLen {
				t.Errorf("DefaultSlotMetadata().ExtKeyUsage len = %v, want %v", len(meta.ExtKeyUsage), tt.wantExtKeyUsageLen)
			}
			if meta.Slot != tt.slot {
				t.Errorf("DefaultSlotMetadata().Slot = %v, want %v", meta.Slot, tt.slot)
			}
			if meta.MaxCertSize != MaxCertSizeFile {
				t.Errorf("DefaultSlotMetadata().MaxCertSize = %v, want %v", meta.MaxCertSize, MaxCertSizeFile)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Test maximum certificate sizes
	if MaxCertSizeFile != 16*1024 {
		t.Errorf("MaxCertSizeFile = %v, want %v", MaxCertSizeFile, 16*1024)
	}
	if MaxCertSizeTPM2 != 4*1024 {
		t.Errorf("MaxCertSizeTPM2 = %v, want %v", MaxCertSizeTPM2, 4*1024)
	}
	if MaxCertSizePKCS11 != 8*1024 {
		t.Errorf("MaxCertSizePKCS11 = %v, want %v", MaxCertSizePKCS11, 8*1024)
	}

	// Test TPM2 NV constants
	if TPM2NVIndexFirst != 0x01000000 {
		t.Errorf("TPM2NVIndexFirst = 0x%x, want 0x01000000", TPM2NVIndexFirst)
	}
	if TPM2NVMagic != 0x50495643 {
		t.Errorf("TPM2NVMagic = 0x%x, want 0x50495643", TPM2NVMagic)
	}
	if TPM2NVVersion != 1 {
		t.Errorf("TPM2NVVersion = %v, want 1", TPM2NVVersion)
	}
	if TPM2NVHeaderSize != 16 {
		t.Errorf("TPM2NVHeaderSize = %v, want 16", TPM2NVHeaderSize)
	}
	if DefaultTPM2BaseIndex != 0x01C00100 {
		t.Errorf("DefaultTPM2BaseIndex = 0x%x, want 0x01C00100", DefaultTPM2BaseIndex)
	}
}

func TestConfigKeyConstants(t *testing.T) {
	// Test Viper configuration key constants
	if ConfigKeyPIVStorage != "piv.storage" {
		t.Errorf("ConfigKeyPIVStorage = %v, want piv.storage", ConfigKeyPIVStorage)
	}
	if ConfigKeyPIVStoragePath != "piv.storage_path" {
		t.Errorf("ConfigKeyPIVStoragePath = %v, want piv.storage_path", ConfigKeyPIVStoragePath)
	}
	if ConfigKeyPIVTPMDevice != "piv.tpm_device" {
		t.Errorf("ConfigKeyPIVTPMDevice = %v, want piv.tpm_device", ConfigKeyPIVTPMDevice)
	}
	if ConfigKeyPIVTPMBaseIndex != "piv.tpm_base_index" {
		t.Errorf("ConfigKeyPIVTPMBaseIndex = %v, want piv.tpm_base_index", ConfigKeyPIVTPMBaseIndex)
	}
	if ConfigKeyPIVTPMOwnerAuth != "piv.tpm_owner_auth" {
		t.Errorf("ConfigKeyPIVTPMOwnerAuth = %v, want piv.tpm_owner_auth", ConfigKeyPIVTPMOwnerAuth)
	}
	if ConfigKeyPIVPKCS11Lib != "piv.pkcs11_library" {
		t.Errorf("ConfigKeyPIVPKCS11Lib = %v, want piv.pkcs11_library", ConfigKeyPIVPKCS11Lib)
	}
	if ConfigKeyPIVPKCS11Token != "piv.pkcs11_token" {
		t.Errorf("ConfigKeyPIVPKCS11Token = %v, want piv.pkcs11_token", ConfigKeyPIVPKCS11Token)
	}
	if ConfigKeyPIVPKCS11SlotID != "piv.pkcs11_slot_id" {
		t.Errorf("ConfigKeyPIVPKCS11SlotID = %v, want piv.pkcs11_slot_id", ConfigKeyPIVPKCS11SlotID)
	}
	if ConfigKeyPIVPKCS11PIN != "piv.pkcs11_pin" {
		t.Errorf("ConfigKeyPIVPKCS11PIN = %v, want piv.pkcs11_pin", ConfigKeyPIVPKCS11PIN)
	}
}

func TestSentinelErrors(t *testing.T) {
	// Test that all sentinel errors have appropriate messages
	sentinelErrors := map[string]error{
		"ErrInvalidSlot":         ErrInvalidSlot,
		"ErrCertificateNotFound": ErrCertificateNotFound,
		"ErrStorageFull":         ErrStorageFull,
		"ErrPermissionDenied":    ErrPermissionDenied,
		"ErrInvalidFormat":       ErrInvalidFormat,
		"ErrStorageClosed":       ErrStorageClosed,
		"ErrInvalidCertificate":  ErrInvalidCertificate,
		"ErrCertificateExpired":  ErrCertificateExpired,
		"ErrCertificateTooLarge": ErrCertificateTooLarge,
		"ErrInvalidConfig":       ErrInvalidConfig,
		"ErrInvalidStorageType":  ErrInvalidStorageType,
		"ErrMissingConfig":       ErrMissingConfig,
		"ErrMissingBackend":      ErrMissingBackend,
		"ErrMissingDevicePath":   ErrMissingDevicePath,
		"ErrMissingLibraryPath":  ErrMissingLibraryPath,
		"ErrNoFormatEnabled":     ErrNoFormatEnabled,
		"ErrTPMNotAvailable":     ErrTPMNotAvailable,
		"ErrPKCS11NotAvailable":  ErrPKCS11NotAvailable,
		"ErrNVIndexExists":       ErrNVIndexExists,
		"ErrNVIndexNotFound":     ErrNVIndexNotFound,
		"ErrTokenNotFound":       ErrTokenNotFound,
		"ErrSessionError":        ErrSessionError,
	}

	for name, err := range sentinelErrors {
		t.Run(name, func(t *testing.T) {
			if err == nil {
				t.Errorf("%s should not be nil", name)
			}
			if err.Error() == "" {
				t.Errorf("%s should have a non-empty error message", name)
			}
			// Check error message starts with "pivcert:"
			if !containsString(err.Error(), "pivcert:") {
				t.Errorf("%s error message should start with 'pivcert:', got: %s", name, err.Error())
			}
		})
	}
}
