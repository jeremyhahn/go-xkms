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

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectDevice_ByLibraryPath verifies that each supported device family is
// recognised from its canonical shared-library name, and that the capability
// flags reported for it match the hardware's real abilities. The capability
// flags gate security decisions (whether a key can be attested, whether DKEK
// wrapping is offered), so a misclassification is a security bug, not cosmetics.
func TestDetectDevice_ByLibraryPath(t *testing.T) {
	tests := []struct {
		name            string
		libraryPath     string
		wantType        DeviceType
		wantAttestation bool
		wantAttestSlot  uint
		wantDKEK        bool
		wantThreshold   bool
	}{
		{
			name:            "yubikey libykcs11",
			libraryPath:     "/usr/lib/libykcs11.so",
			wantType:        DeviceTypeYubiKey,
			wantAttestation: true,
			wantAttestSlot:  0xF9,
		},
		{
			name:            "yubikey windows dll",
			libraryPath:     "C:\\Program Files\\Yubico\\ykcs11.dll",
			wantType:        DeviceTypeYubiKey,
			wantAttestation: true,
			wantAttestSlot:  0xF9,
		},
		{
			name:            "opensc is smartcard-hsm",
			libraryPath:     "/usr/lib/opensc-pkcs11.so",
			wantType:        DeviceTypeSmartCardHSM,
			wantAttestation: true,
			wantDKEK:        true,
			wantThreshold:   true,
		},
		{
			name:            "sc-hsm library",
			libraryPath:     "/usr/lib/libsc-hsm-pkcs11.so",
			wantType:        DeviceTypeSmartCardHSM,
			wantAttestation: true,
			wantDKEK:        true,
			wantThreshold:   true,
		},
		{
			name:        "softhsm2 has no hardware guarantees",
			libraryPath: "/usr/lib/softhsm/libsofthsm2.so",
			wantType:    DeviceTypeSoftHSM,
		},
		{
			name:        "unknown vendor falls back to generic",
			libraryPath: "/opt/vendor/libcustomtoken.so",
			wantType:    DeviceTypeGenericPKCS11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDevice(tt.libraryPath, SlotInfo{})

			assert.Equal(t, tt.wantType, got.Type)
			assert.Equal(t, tt.wantAttestation, got.SupportsAttestation,
				"attestation support gates whether callers trust an attestation statement")
			assert.Equal(t, tt.wantAttestSlot, got.AttestationSlot)
			assert.Equal(t, tt.wantDKEK, got.SupportsDKEK)
			assert.Equal(t, tt.wantThreshold, got.SupportsThreshold)
		})
	}
}

// TestDetectDevice_ByTokenMetadata verifies detection works from the token's
// own CK_TOKEN_INFO strings, which is the only signal available when a device
// is reached through a generic library such as opensc or a vendor-neutral path.
func TestDetectDevice_ByTokenMetadata(t *testing.T) {
	tests := []struct {
		name            string
		libraryPath     string
		slot            SlotInfo
		wantType        DeviceType
		wantDisplayName string
	}{
		{
			name:            "yubico manufacturer through neutral library",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Manufacturer: "Yubico (www.yubico.com)"},
			wantType:        DeviceTypeYubiKey,
			wantDisplayName: "YubiKey",
		},
		{
			name:            "yubikey label through neutral library",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Label: "YubiKey PIV #12345"},
			wantType:        DeviceTypeYubiKey,
			wantDisplayName: "YubiKey PIV #12345",
		},
		{
			name:            "cardcontact manufacturer",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Manufacturer: "CardContact (www.cardcontact.de)"},
			wantType:        DeviceTypeSmartCardHSM,
			wantDisplayName: "SmartCard-HSM",
		},
		{
			name:            "smartcard-hsm model",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Model: "SmartCard-HSM"},
			wantType:        DeviceTypeSmartCardHSM,
			wantDisplayName: "SmartCard-HSM",
		},
		{
			name:            "nitrokey gets its own display name",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Manufacturer: "Nitrokey"},
			wantType:        DeviceTypeSmartCardHSM,
			wantDisplayName: "Nitrokey HSM",
		},
		{
			name:            "nitrokey by model gets its own display name",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Model: "Nitrokey HSM 2"},
			wantType:        DeviceTypeSmartCardHSM,
			wantDisplayName: "Nitrokey HSM 2",
		},
		{
			name:            "softhsm project manufacturer",
			libraryPath:     "/opt/vendor/libgeneric.so",
			slot:            SlotInfo{Manufacturer: "SoftHSM project"},
			wantType:        DeviceTypeSoftHSM,
			wantDisplayName: "SoftHSM2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDevice(tt.libraryPath, tt.slot)

			assert.Equal(t, tt.wantType, got.Type)
			assert.Equal(t, tt.wantDisplayName, got.DisplayName)
		})
	}
}

// TestDetectDevice_MatchingIsCaseInsensitive guards the strings.ToLower
// normalisation. Real tokens report mixed-case manufacturer strings, so a
// regression that dropped the normalisation would silently downgrade a
// YubiKey to a generic token and lose attestation support.
func TestDetectDevice_MatchingIsCaseInsensitive(t *testing.T) {
	upper := DetectDevice("/opt/LIBYKCS11.SO", SlotInfo{Manufacturer: "YUBICO"})
	lower := DetectDevice("/opt/libykcs11.so", SlotInfo{Manufacturer: "yubico"})

	assert.Equal(t, DeviceTypeYubiKey, upper.Type)
	assert.Equal(t, lower.Type, upper.Type)
	assert.True(t, upper.SupportsAttestation)
}

// TestDetectDevice_YubiKeyWinsOverSmartCardHSM pins the documented matching
// order. A YubiKey is commonly driven through opensc-pkcs11.so, whose name also
// matches the SmartCard-HSM rule. YubiKey must win, otherwise the device would
// be credited with DKEK and threshold support it does not have.
func TestDetectDevice_YubiKeyWinsOverSmartCardHSM(t *testing.T) {
	got := DetectDevice("/usr/lib/opensc-pkcs11.so", SlotInfo{Manufacturer: "Yubico"})

	require.Equal(t, DeviceTypeYubiKey, got.Type)
	assert.False(t, got.SupportsDKEK, "YubiKey PIV has no DKEK support")
	assert.False(t, got.SupportsThreshold, "YubiKey PIV has no M-of-N share support")
	assert.Equal(t, uint(0xF9), got.AttestationSlot)
}

// TestDetectDevice_SoftHSMNeverClaimsHardwareGuarantees is a security
// regression guard: a software token must never be reported as attestation
// capable, because callers use that flag to decide whether a key can be proven
// to live in hardware.
func TestDetectDevice_SoftHSMNeverClaimsHardwareGuarantees(t *testing.T) {
	got := DetectDevice("/usr/lib/softhsm/libsofthsm2.so", SlotInfo{
		Manufacturer: "SoftHSM project",
		Model:        "SoftHSM v2",
		Label:        "test-token",
	})

	require.Equal(t, DeviceTypeSoftHSM, got.Type)
	assert.False(t, got.SupportsAttestation)
	assert.False(t, got.SupportsDKEK)
	assert.False(t, got.SupportsThreshold)
	assert.Zero(t, got.AttestationSlot)
	assert.False(t, got.Type.IsHardwareBacked())
}

// TestBuildDisplayName_Precedence verifies the label > model > fallback order
// used to name a device in the UI. Two tokens in different slots of the same
// module share a model string, so preferring the label is what keeps them
// distinguishable to an operator.
func TestBuildDisplayName_Precedence(t *testing.T) {
	tests := []struct {
		name     string
		baseName string
		slot     SlotInfo
		want     string
	}{
		{
			name:     "label wins over model",
			baseName: "YubiKey",
			slot:     SlotInfo{Label: "PIV Card A", Model: "YubiKey 5"},
			want:     "PIV Card A",
		},
		{
			name:     "model used when label empty",
			baseName: "YubiKey",
			slot:     SlotInfo{Model: "YubiKey 5"},
			want:     "YubiKey 5",
		},
		{
			name:     "base name used when label and model empty",
			baseName: "PKCS#11 Token",
			slot:     SlotInfo{},
			want:     "PKCS#11 Token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildDisplayName(tt.baseName, tt.slot))
		})
	}
}

// TestDeviceType_IsHardwareBacked pins which device families may be treated as
// hardware-backed. This flag decides whether a key is allowed to satisfy a
// hardware-custody policy, so an unknown or software type must fail closed.
func TestDeviceType_IsHardwareBacked(t *testing.T) {
	tests := []struct {
		deviceType DeviceType
		want       bool
	}{
		{DeviceTypeYubiKey, true},
		{DeviceTypeSmartCardHSM, true},
		{DeviceTypeSoftHSM, false},
		{DeviceTypeGenericPKCS11, false},
		{DeviceType("not-a-real-device"), false},
		{DeviceType(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.deviceType), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.deviceType.IsHardwareBacked())
		})
	}
}

// TestDeviceType_String checks the wire/JSON representation is the bare device
// identifier, which config files and the REST API both persist.
func TestDeviceType_String(t *testing.T) {
	assert.Equal(t, "yubikey", DeviceTypeYubiKey.String())
	assert.Equal(t, "smartcardhsm", DeviceTypeSmartCardHSM.String())
	assert.Equal(t, "softhsm", DeviceTypeSoftHSM.String())
	assert.Equal(t, "pkcs11", DeviceTypeGenericPKCS11.String())
	assert.Equal(t, "", DeviceType("").String())
}
