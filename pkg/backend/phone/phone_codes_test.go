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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

func TestMapRPCError_PhoneOnlyCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected error
	}{
		{"biometric not enrolled", pairingproto.ErrorCodeBiometricNotEnrolled, pairingproto.ErrBiometricNotEnrolled},
		{"biometric lockout", pairingproto.ErrorCodeBiometricLockout, pairingproto.ErrBiometricLockout},
		{"key generation failed", pairingproto.ErrorCodeKeyGenerationFailed, pairingproto.ErrKeyGenerationFailed},
		{"signing failed", pairingproto.ErrorCodeSigningFailed, pairingproto.ErrSigningFailed},
		{"encryption failed", pairingproto.ErrorCodeEncryptionFailed, pairingproto.ErrEncryptionFailed},
		{"strongbox unavailable", pairingproto.ErrorCodeStrongBoxUnavailable, pairingproto.ErrStrongBoxUnavailable},
		{"session expired", pairingproto.ErrorCodeSessionExpired, pairingproto.ErrSessionExpired},
		{"rate limited", pairingproto.ErrorCodeRateLimited, pairingproto.ErrRateLimited},
		{"export failed", pairingproto.ErrorCodeExportFailed, pairingproto.ErrExportFailed},
		{"device attestation required", pairingproto.ErrorCodeDeviceAttestationRequired, pairingproto.ErrDeviceAttestationRequired},
		{"pairing required", pairingproto.ErrorCodePairingRequired, pairingproto.ErrPairingRequired},
		{"pin required", pairingproto.ErrorCodePINRequired, pairingproto.ErrPINRequired},
		{"pin incorrect", pairingproto.ErrorCodePINIncorrect, pairingproto.ErrPINIncorrect},
		{"pin locked", pairingproto.ErrorCodePINLocked, pairingproto.ErrPINLocked},
		{"vault not initialized", pairingproto.ErrorCodeVaultNotInitialized, pairingproto.ErrVaultNotInitialized},
		{"vault credential rejected", pairingproto.ErrorCodeVaultCredentialRejected, pairingproto.ErrVaultCredentialRejected},
		{"password store locked", pairingproto.ErrorCodePasswordStoreLocked, pairingproto.ErrPasswordStoreLocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapRPCError(&pairingproto.RPCError{Code: tt.code}))
		})
	}
}
