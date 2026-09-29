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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

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
