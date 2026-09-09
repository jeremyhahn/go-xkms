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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSOPIN = "so-pin-12345678"

// sealPolicy writes the HMAC for cfg.Policy under soPIN into configDir, the
// way SO provisioning does, and returns the config directory.
func sealPolicy(t *testing.T, cfg *Config, soPIN string) string {
	t.Helper()
	configDir := t.TempDir()
	require.NoError(t, WritePolicyHMAC(&cfg.Policy, soPIN, PolicyHMACPath(configDir)))
	return configDir
}

// permissiveEnterpriseConfig is a policy an SO might legitimately seal: the
// pairing setting locked OPEN, which only an authenticated section may grant.
func permissiveEnterpriseConfig() *Config {
	cfg := DefaultConfig()
	cfg.Policy.LockPairingAttestationPolicy = true
	cfg.Policy.PairingAllowUnattestableDevices = true
	cfg.Policy.ExtensionRequireAuthentication = false
	return cfg
}

func TestLoadVerifiedPolicy_UnsealedReturnsTheSectionAsRead(t *testing.T) {
	cfg := permissiveEnterpriseConfig()

	vp, err := LoadVerifiedPolicy(cfg, t.TempDir(), "")
	require.NoError(t, err)

	assert.Equal(t, PolicyUnsealed, vp.State)
	assert.Equal(t, cfg.Policy, vp.Policy)
}

func TestLoadVerifiedPolicy_UnsealedIgnoresASuppliedPIN(t *testing.T) {
	cfg := DefaultConfig()

	vp, err := LoadVerifiedPolicy(cfg, t.TempDir(), testSOPIN)
	require.NoError(t, err)
	assert.Equal(t, PolicyUnsealed, vp.State)
}

// TestLoadVerifiedPolicy_SealedAndVerifiedIsHonouredPermissively is the test
// that separates this accessor from the monotone mitigation: a correctly
// sealed permissive policy comes back with the permissive values intact.
func TestLoadVerifiedPolicy_SealedAndVerifiedIsHonouredPermissively(t *testing.T) {
	cfg := permissiveEnterpriseConfig()
	configDir := sealPolicy(t, cfg, testSOPIN)

	vp, err := LoadVerifiedPolicy(cfg, configDir, testSOPIN)
	require.NoError(t, err)

	assert.Equal(t, PolicySealedVerified, vp.State)
	assert.True(t, vp.Policy.LockPairingAttestationPolicy)
	assert.True(t, vp.Policy.PairingAllowUnattestableDevices)
	assert.False(t, vp.Policy.ExtensionRequireAuthentication)
}

// TestLoadVerifiedPolicy_SealedTamperedPermissivelyIsRefused is the fail-open
// Codex found on #110: the SO sealed a strict policy, a local user edited the
// file to the permissive values, and the result must be a refusal, never the
// edited section.
func TestLoadVerifiedPolicy_SealedTamperedPermissivelyIsRefused(t *testing.T) {
	sealed := DefaultConfig()
	configDir := sealPolicy(t, sealed, testSOPIN)

	tampered := permissiveEnterpriseConfig()
	vp, err := LoadVerifiedPolicy(tampered, configDir, testSOPIN)

	require.Error(t, err)
	assert.Nil(t, vp)
	assert.ErrorIs(t, err, ErrPolicyUnverifiable)
	assert.ErrorIs(t, err, ErrPolicyHMACMismatch)
}

func TestLoadVerifiedPolicy_SealedWithoutPINIsRefused(t *testing.T) {
	cfg := permissiveEnterpriseConfig()
	configDir := sealPolicy(t, cfg, testSOPIN)

	vp, err := LoadVerifiedPolicy(cfg, configDir, "")

	require.Error(t, err)
	assert.Nil(t, vp)
	assert.ErrorIs(t, err, ErrPolicyUnverifiable)
	assert.ErrorIs(t, err, ErrPolicySOPINRequired)
}

func TestLoadVerifiedPolicy_SealedWithWrongPINIsRefused(t *testing.T) {
	cfg := permissiveEnterpriseConfig()
	configDir := sealPolicy(t, cfg, testSOPIN)

	vp, err := LoadVerifiedPolicy(cfg, configDir, "not-the-so-pin")

	require.Error(t, err)
	assert.Nil(t, vp)
	assert.ErrorIs(t, err, ErrPolicyUnverifiable)
	assert.ErrorIs(t, err, ErrPolicyHMACMismatch)
}

// TestLoadVerifiedPolicy_SealedWithCorruptHMACFileIsRefused covers the
// "invalid" leg: the marker file exists, so the directory is sealed, but the
// record cannot be read. That is unverifiable, not unsealed.
func TestLoadVerifiedPolicy_SealedWithCorruptHMACFileIsRefused(t *testing.T) {
	cfg := permissiveEnterpriseConfig()
	configDir := t.TempDir()
	require.NoError(t, os.WriteFile(PolicyHMACPath(configDir), []byte("{not json"), 0600))

	vp, err := LoadVerifiedPolicy(cfg, configDir, testSOPIN)

	require.Error(t, err)
	assert.Nil(t, vp)
	assert.ErrorIs(t, err, ErrPolicyUnverifiable)
	assert.ErrorIs(t, err, ErrPolicyHMACLoadFailed)
}

func TestLoadVerifiedPolicy_NilConfigIsRefused(t *testing.T) {
	vp, err := LoadVerifiedPolicy(nil, t.TempDir(), testSOPIN)
	require.Error(t, err)
	assert.Nil(t, vp)
	assert.ErrorIs(t, err, ErrConfigInvalid)
}

func TestPolicyState_String(t *testing.T) {
	assert.Equal(t, "unsealed", PolicyUnsealed.String())
	assert.Equal(t, "sealed-verified", PolicySealedVerified.String())
	assert.Equal(t, "unknown", PolicyState(99).String())
}
