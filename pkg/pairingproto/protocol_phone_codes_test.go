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

package pairingproto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phoneOnlyCodes lists the reserved phone-only block -32041..-32057.
var phoneOnlyCodes = []struct {
	name     string
	code     int
	value    int
	sentinel error
}{
	{"BiometricNotEnrolled", ErrorCodeBiometricNotEnrolled, -32041, ErrBiometricNotEnrolled},
	{"BiometricLockout", ErrorCodeBiometricLockout, -32042, ErrBiometricLockout},
	{"KeyGenerationFailed", ErrorCodeKeyGenerationFailed, -32043, ErrKeyGenerationFailed},
	{"SigningFailed", ErrorCodeSigningFailed, -32044, ErrSigningFailed},
	{"EncryptionFailed", ErrorCodeEncryptionFailed, -32045, ErrEncryptionFailed},
	{"StrongBoxUnavailable", ErrorCodeStrongBoxUnavailable, -32046, ErrStrongBoxUnavailable},
	{"SessionExpired", ErrorCodeSessionExpired, -32047, ErrSessionExpired},
	{"RateLimited", ErrorCodeRateLimited, -32048, ErrRateLimited},
	{"ExportFailed", ErrorCodeExportFailed, -32049, ErrExportFailed},
	{"DeviceAttestationRequired", ErrorCodeDeviceAttestationRequired, -32050, ErrDeviceAttestationRequired},
	{"PairingRequired", ErrorCodePairingRequired, -32051, ErrPairingRequired},
	{"PINRequired", ErrorCodePINRequired, -32052, ErrPINRequired},
	{"PINIncorrect", ErrorCodePINIncorrect, -32053, ErrPINIncorrect},
	{"PINLocked", ErrorCodePINLocked, -32054, ErrPINLocked},
	{"VaultNotInitialized", ErrorCodeVaultNotInitialized, -32055, ErrVaultNotInitialized},
	{"VaultCredentialRejected", ErrorCodeVaultCredentialRejected, -32056, ErrVaultCredentialRejected},
	{"PasswordStoreLocked", ErrorCodePasswordStoreLocked, -32057, ErrPasswordStoreLocked},
}

func TestPhoneOnlyErrorCodes_Values(t *testing.T) {
	for _, tt := range phoneOnlyCodes {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.value, tt.code)
		})
	}
}

func TestPhoneOnlyErrorCodes_MapToOwnSentinel(t *testing.T) {
	seen := make(map[error]string)
	for _, tt := range phoneOnlyCodes {
		t.Run(tt.name, func(t *testing.T) {
			require.NotNil(t, tt.sentinel)
			mapped, ok := rpcErrorMap[tt.code]
			require.True(t, ok, "code %d is not in rpcErrorMap", tt.code)
			assert.Equal(t, tt.sentinel, mapped)
			assert.ErrorIs(t, MapRPCError(&RPCError{Code: tt.code}), tt.sentinel)
		})
		if prev, dup := seen[tt.sentinel]; dup {
			t.Errorf("%s and %s share a sentinel", prev, tt.name)
		}
		seen[tt.sentinel] = tt.name
	}
	for code, sentinel := range rpcErrorMap {
		name, ok := seen[sentinel]
		if !ok {
			continue
		}
		for _, tt := range phoneOnlyCodes {
			if tt.name == name && tt.code != code {
				t.Errorf("sentinel of %s is also mapped from code %d", name, code)
			}
		}
	}
}

func TestErrorCodes_Unique(t *testing.T) {
	codes := map[string]int{
		"ParseError":                ErrorCodeParseError,
		"InvalidRequest":            ErrorCodeInvalidRequest,
		"MethodNotFound":            ErrorCodeMethodNotFound,
		"InvalidParams":             ErrorCodeInvalidParams,
		"InternalError":             ErrorCodeInternalError,
		"KeyNotFound":               ErrorCodeKeyNotFound,
		"UserCancelled":             ErrorCodeUserCancelled,
		"BiometricFailed":           ErrorCodeBiometricFailed,
		"KeyExists":                 ErrorCodeKeyExists,
		"UnsupportedAlg":            ErrorCodeUnsupportedAlg,
		"InvalidCredID":             ErrorCodeInvalidCredID,
		"StorageFull":               ErrorCodeStorageFull,
		"OperationTimeout":          ErrorCodeOperationTimeout,
		"BackendDenied":             ErrorCodeBackendDenied,
		"AttestFailed":              ErrorCodeAttestFailed,
		"AttestUnsupported":         ErrorCodeAttestUnsupported,
		"OperationDenied":           ErrorCodeOperationDenied,
		"InvalidPublicKey":          ErrorCodeInvalidPublicKey,
		"DecryptFailed":             ErrorCodeDecryptFailed,
		"HMACFailed":                ErrorCodeHMACFailed,
		"ECDHFailed":                ErrorCodeECDHFailed,
		"InvalidFormat":             ErrorCodeInvalidFormat,
		"PairingRejected":           ErrorCodePairingRejected,
		"ShareDenied":               ErrorCodeShareDenied,
		"ShareNotExportable":        ErrorCodeShareNotExportable,
		"BackupFailed":              ErrorCodeBackupFailed,
		"BackupRestore":             ErrorCodeBackupRestore,
		"BackupNotFound":            ErrorCodeBackupNotFound,
		"OATHNotFound":              ErrorCodeOATHNotFound,
		"OATHGenerate":              ErrorCodeOATHGenerate,
		"OATHStore":                 ErrorCodeOATHStore,
		"PIVSlotNotFound":           ErrorCodePIVSlotNotFound,
		"PIVSlotOccupied":           ErrorCodePIVSlotOccupied,
		"PIVSignFailed":             ErrorCodePIVSignFailed,
		"PIVInvalidSlot":            ErrorCodePIVInvalidSlot,
		"SyncFailed":                ErrorCodeSyncFailed,
		"SyncConflict":              ErrorCodeSyncConflict,
		"SyncRemoteUnavail":         ErrorCodeSyncRemoteUnavail,
		"SyncNoData":                ErrorCodeSyncNoData,
		"SyncVersionMismatch":       ErrorCodeSyncVersionMismatch,
		"FeatureUnavailable":        ErrorCodeFeatureUnavailable,
		"NotApplicable":             ErrorCodeNotApplicable,
		"AttestProtocolDowngrade":   ErrorCodeAttestProtocolDowngrade,
		"SyncApprovalRequired":      ErrorCodeSyncApprovalRequired,
		"SyncNotApproved":           ErrorCodeSyncNotApproved,
		"MessageTooLarge":           ErrorCodeMessageTooLarge,
		"BiometricNotEnrolled":      ErrorCodeBiometricNotEnrolled,
		"BiometricLockout":          ErrorCodeBiometricLockout,
		"KeyGenerationFailed":       ErrorCodeKeyGenerationFailed,
		"SigningFailed":             ErrorCodeSigningFailed,
		"EncryptionFailed":          ErrorCodeEncryptionFailed,
		"StrongBoxUnavailable":      ErrorCodeStrongBoxUnavailable,
		"SessionExpired":            ErrorCodeSessionExpired,
		"RateLimited":               ErrorCodeRateLimited,
		"ExportFailed":              ErrorCodeExportFailed,
		"DeviceAttestationRequired": ErrorCodeDeviceAttestationRequired,
		"PairingRequired":           ErrorCodePairingRequired,
		"PINRequired":               ErrorCodePINRequired,
		"PINIncorrect":              ErrorCodePINIncorrect,
		"PINLocked":                 ErrorCodePINLocked,
		"VaultNotInitialized":       ErrorCodeVaultNotInitialized,
		"VaultCredentialRejected":   ErrorCodeVaultCredentialRejected,
		"PasswordStoreLocked":       ErrorCodePasswordStoreLocked,
	}
	byValue := make(map[int]string, len(codes))
	for name, code := range codes {
		if prev, dup := byValue[code]; dup {
			t.Errorf("ErrorCode%s and ErrorCode%s share value %d", prev, name, code)
		}
		byValue[code] = name
	}
}
