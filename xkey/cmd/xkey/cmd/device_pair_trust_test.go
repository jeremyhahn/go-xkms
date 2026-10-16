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

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// applicationLockedConfig is the policy a fleet that locks the attested-
// application allow-list would seal (#1305): a narrower list than whatever an
// operator might write into devices.yaml.
func applicationLockedConfig() *xkeyconfig.Config {
	cfg := xkeyconfig.DefaultConfig()
	cfg.Policy.LockPairingApplicationPolicy = true
	cfg.Policy.PairingAllowedApplications = []pairing.AllowedApplication{{
		PackageName:    "com.automatethethings.xkey",
		SigningDigests: []string{"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"},
	}}
	return cfg
}

// sealPolicyFixtureNoCommand seals cfg's policy into a fresh config directory
// without a *cobra.Command: resolveEnterpriseApplicationPolicy reads
// XKEY_SO_PIN directly, the same env-only path a deep re-attestation call
// graph with no command in hand must use.
func sealPolicyFixtureNoCommand(t *testing.T, cfg *xkeyconfig.Config, soPIN string) {
	t.Helper()
	configDir := t.TempDir()
	xkeyconfig.SetConfigDir(configDir)
	t.Cleanup(xkeyconfig.ResetConfigDir)
	if soPIN != "" {
		require.NoError(t, xkeyconfig.WritePolicyHMAC(&cfg.Policy, soPIN, xkeyconfig.PolicyHMACPath(configDir)))
	}
}

// TestAllowUnattestablePairing_FailsClosedWithoutAPolicy pins the default:
// with no verified policy in hand, devices.yaml's own opt-in cannot let an
// unattestable device pair.
func TestAllowUnattestablePairing_FailsClosedWithoutAPolicy(t *testing.T) {
	userAllows := &DevicesConfig{AttestationPolicy: &AttestationPolicy{AllowUnattestableDevices: true}}

	require.False(t, allowUnattestablePairing(userAllows, nil))
	require.False(t, allowUnattestablePairing(nil, nil))
}

// TestAllowUnattestablePairing_UserSettingGovernsAnUnlockedPolicy covers the
// verified-but-unlocked policy: the user's devices.yaml decides, and a
// missing devices.yaml or attestation block means no.
func TestAllowUnattestablePairing_UserSettingGovernsAnUnlockedPolicy(t *testing.T) {
	policy := &xkeyconfig.VerifiedPolicy{}

	require.True(t, allowUnattestablePairing(
		&DevicesConfig{AttestationPolicy: &AttestationPolicy{AllowUnattestableDevices: true}}, policy))
	require.False(t, allowUnattestablePairing(&DevicesConfig{}, policy))
	require.False(t, allowUnattestablePairing(nil, policy))
}

// TestAllowUnattestablePairing_LockedPolicyOverridesTheUser pins the SO's
// lock: while it is set, the sealed policy's answer wins either way.
func TestAllowUnattestablePairing_LockedPolicyOverridesTheUser(t *testing.T) {
	userAllows := &DevicesConfig{AttestationPolicy: &AttestationPolicy{AllowUnattestableDevices: true}}
	locked := &xkeyconfig.VerifiedPolicy{}
	locked.Policy.LockPairingAttestationPolicy = true

	require.False(t, allowUnattestablePairing(userAllows, locked))

	locked.Policy.PairingAllowUnattestableDevices = true
	require.True(t, allowUnattestablePairing(&DevicesConfig{}, locked))
}

// TestLoadPairingAttestationTrust_SealedUnverifiedRefusesDespiteDevicesYAML
// is the end-to-end proof of the fix for the bypass a locked enterprise
// allow-list exists to prevent (#1305): devices.yaml carries a perfectly
// valid, configured allow-list, but this machine's config directory is
// sealed and XKEY_SO_PIN is not set, so loadPairingAttestationTrust must
// refuse outright -- never silently fall back to reading it.
func TestLoadPairingAttestationTrust_SealedUnverifiedRefusesDespiteDevicesYAML(t *testing.T) {
	isolatePairingTrust(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		AttestationPolicy: &AttestationPolicy{ApplicationPolicy: attesttest.Applications()},
	}))
	sealPolicyFixtureNoCommand(t, applicationLockedConfig(), testSOPIN)
	// XKEY_SO_PIN intentionally left unset: this deployment is sealed but
	// nothing here proves it to loadPairingAttestationTrust.

	trust, err := loadPairingAttestationTrust()
	require.ErrorIs(t, err, attestation.ErrApplicationPolicyUnverifiable)
	require.Nil(t, trust)
}

// isolatePairingTrust points the trust store and devices.yaml at a fresh
// temporary home, and returns the devices.yaml path.
func isolatePairingTrust(t *testing.T) string {
	t.Helper()
	resetViperForTest(t)
	viper.Set("trust.store_path", t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_USER", "")

	path, err := getDevicesConfigPath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	return path
}

// TestLoadPairingAttestationTrust_EmptyStore exercises the real
// openTrustStore + attestation.LoadTrust path against a fresh, empty
// on-disk trust store: no custom roots configured, but the load itself must
// succeed, carrying devices.yaml's application allow-list (#1305).
func TestLoadPairingAttestationTrust_EmptyStore(t *testing.T) {
	path := isolatePairingTrust(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		AttestationPolicy: &AttestationPolicy{ApplicationPolicy: attesttest.Applications()},
	}))
	_, err := os.Stat(path)
	require.NoError(t, err)

	trust, err := loadPairingAttestationTrust()
	require.NoError(t, err)
	require.NotNil(t, trust)
	require.Equal(t, attesttest.Applications(), trust.Applications)
}

// TestLoadPairingAttestationTrust_RefusesWithoutAnAllowList pins #1305's fail
// closed default on the CLI: with no devices.yaml, or one whose
// attestation_policy lists no application, every pairing and re-attestation
// is refused with the configuration error, before any phone is asked.
func TestLoadPairingAttestationTrust_RefusesWithoutAnAllowList(t *testing.T) {
	path := isolatePairingTrust(t)

	trust, err := loadPairingAttestationTrust()
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	require.ErrorIs(t, err, pairing.ErrApplicationPolicyUnconfigured)
	require.Nil(t, trust)

	require.NoError(t, os.WriteFile(path, []byte("attestation_policy:\n  allow_unattestable_devices: false\n"), 0o600))
	trust, err = loadPairingAttestationTrust()
	require.ErrorIs(t, err, pairing.ErrApplicationPolicyUnconfigured)
	require.Nil(t, trust)
}

// TestLoadPairingAttestationTrust_RefusesAnUnreadableDevicesConfig pins that a
// devices.yaml that exists but cannot be parsed refuses outright instead of
// being mistaken for an absent policy.
func TestLoadPairingAttestationTrust_RefusesAnUnreadableDevicesConfig(t *testing.T) {
	path := isolatePairingTrust(t)
	require.NoError(t, os.WriteFile(path, []byte("attestation_policy: [not, a, map\n"), 0o600))

	trust, err := loadPairingAttestationTrust()
	require.ErrorIs(t, err, ErrDeviceConfigLoadFailed)
	require.Nil(t, trust)
}

// TestDevicesConfigReadsTheApplicationAllowList pins the devices.yaml shape
// the allow-list is configured in: its keys sit directly in the
// attestation_policy block, beside the settings already there.
func TestDevicesConfigReadsTheApplicationAllowList(t *testing.T) {
	path := isolatePairingTrust(t)
	require.NoError(t, os.WriteFile(path, []byte(`attestation_policy:
  allow_unattestable_devices: false
  allowed_applications:
    - package_name: com.automatethethings.xkey
      signing_digests:
        - 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
`), 0o600))

	cfg, err := loadDevicesConfig()
	require.NoError(t, err)
	require.Equal(t, attesttest.Applications(), cfg.applicationPolicy())

	require.Equal(t, pairing.ApplicationPolicy{}, (&DevicesConfig{}).applicationPolicy())
	require.Equal(t, pairing.ApplicationPolicy{}, (*DevicesConfig)(nil).applicationPolicy())
}
