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

//go:build ble

package cmd

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIsDeviceAttestationRequired_NeverAttested(t *testing.T) {
	device := &PairedDevice{}
	require.True(t, isDeviceAttestationRequired(device, nil))
}

func TestIsDeviceAttestationRequired_WithinDeviceGracePeriod(t *testing.T) {
	device := &PairedDevice{
		LastDeviceAttestationTime: time.Now().Add(-time.Minute),
		AttestationGracePeriod:    Duration(time.Hour),
	}
	require.False(t, isDeviceAttestationRequired(device, nil))
}

func TestIsDeviceAttestationRequired_PastDeviceGracePeriod(t *testing.T) {
	device := &PairedDevice{
		LastDeviceAttestationTime: time.Now().Add(-2 * time.Hour),
		AttestationGracePeriod:    Duration(time.Hour),
	}
	require.True(t, isDeviceAttestationRequired(device, nil))
}

func TestIsDeviceAttestationRequired_PolicyGracePeriodFallback(t *testing.T) {
	device := &PairedDevice{LastDeviceAttestationTime: time.Now().Add(-2 * time.Minute)}
	policy := &AttestationPolicy{DefaultGracePeriod: Duration(time.Hour)}
	require.False(t, isDeviceAttestationRequired(device, policy))
}

func TestIsDeviceAttestationRequired_SystemDefaultFallback(t *testing.T) {
	device := &PairedDevice{LastDeviceAttestationTime: time.Now().Add(-time.Hour)}
	require.True(t, isDeviceAttestationRequired(device, nil),
		"the system default grace period (5m) has elapsed")
}

func TestValidateBootHashMatch_FirstAttestation(t *testing.T) {
	device := &PairedDevice{}
	require.NoError(t, validateBootHashMatch(device, "freshhash"))
}

func TestValidateBootHashMatch_Matching(t *testing.T) {
	device := &PairedDevice{DeviceBootHashHex: "deadbeef"}
	require.NoError(t, validateBootHashMatch(device, "deadbeef"))
}

func TestValidateBootHashMatch_Mismatch(t *testing.T) {
	device := &PairedDevice{DeviceBootHashHex: "deadbeef"}
	err := validateBootHashMatch(device, "cafebabe")
	require.ErrorIs(t, err, ErrBootHashMismatch)
}

func TestValidateSecurityLevel_NoPolicy(t *testing.T) {
	require.NoError(t, validateSecurityLevel("software", nil))
	require.NoError(t, validateSecurityLevel("software", &AttestationPolicy{}))
}

func TestValidateSecurityLevel_MeetsMinimum(t *testing.T) {
	policy := &AttestationPolicy{MinSecurityLevel: "tee"}
	require.NoError(t, validateSecurityLevel("strongbox", policy))
	require.NoError(t, validateSecurityLevel("tee", policy))
}

func TestValidateSecurityLevel_BelowMinimum(t *testing.T) {
	policy := &AttestationPolicy{MinSecurityLevel: "strongbox"}
	err := validateSecurityLevel("tee", policy)
	require.ErrorIs(t, err, ErrSecurityLevelInsufficient)

	var detail *DetailError
	require.True(t, errors.As(err, &detail))
	require.Contains(t, detail.Detail, "tee")
	require.Contains(t, detail.Detail, "strongbox")
}

func TestValidateSecurityLevel_UnknownActualLevel(t *testing.T) {
	policy := &AttestationPolicy{MinSecurityLevel: "tee"}
	err := validateSecurityLevel("quantum", policy)
	require.ErrorIs(t, err, ErrSecurityLevelInsufficient)
	require.Contains(t, err.Error(), "unknown level quantum")
}

func TestValidateSecurityLevel_UnknownPolicyLevelSkipsCheck(t *testing.T) {
	policy := &AttestationPolicy{MinSecurityLevel: "quantum"}
	require.NoError(t, validateSecurityLevel("software", policy),
		"an unrecognized policy minimum is invalid configuration, not a refusal")
}

func TestFormatAttestationDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"seconds", 45 * time.Second, "45s"},
		{"minutes", 90 * time.Second, "1m 30s"},
		{"hours", 2*time.Hour + 15*time.Minute, "2h 15m"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, formatAttestationDuration(tc.d))
		})
	}
}

func TestTimeRemaining_NeverAttested(t *testing.T) {
	device := &PairedDevice{}
	require.Zero(t, timeRemaining(device, nil))
}

func TestTimeRemaining_WithinGracePeriod(t *testing.T) {
	device := &PairedDevice{
		LastDeviceAttestationTime: time.Now().Add(-time.Minute),
		AttestationGracePeriod:    Duration(time.Hour),
	}
	got := timeRemaining(device, nil)
	require.Greater(t, got, time.Duration(0))
	require.LessOrEqual(t, got, time.Hour)
}

func TestTimeRemaining_ElapsedGracePeriod(t *testing.T) {
	device := &PairedDevice{
		LastDeviceAttestationTime: time.Now().Add(-2 * time.Hour),
		AttestationGracePeriod:    Duration(time.Hour),
	}
	require.Zero(t, timeRemaining(device, nil))
}

func TestTimeRemaining_PolicyFallback(t *testing.T) {
	device := &PairedDevice{LastDeviceAttestationTime: time.Now().Add(-30 * time.Second)}
	policy := &AttestationPolicy{DefaultGracePeriod: Duration(time.Minute)}
	got := timeRemaining(device, policy)
	require.Greater(t, got, time.Duration(0))
	require.LessOrEqual(t, got, time.Minute)
}
