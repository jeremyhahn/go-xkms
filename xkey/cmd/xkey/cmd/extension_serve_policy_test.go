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

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// testSOPIN is the Security Officer PIN the policy fixtures seal under.
const testSOPIN = "so-pin-12345678"

// sealServePolicy seals cfg's policy under soPIN into a fresh config
// directory and returns the directory. An empty soPIN leaves the directory
// unsealed.
func sealServePolicy(t *testing.T, cfg *config.Config, soPIN string) string {
	t.Helper()

	configDir := t.TempDir()
	if soPIN != "" {
		require.NoError(t, config.WritePolicyHMAC(&cfg.Policy, soPIN, config.PolicyHMACPath(configDir)))
	}
	return configDir
}

// relaxedExtensionConfig is a policy an SO might legitimately seal: CTAP2
// authentication for autofill switched off, which only a verified section
// may grant.
func relaxedExtensionConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Policy.ExtensionRequireAuthentication = false
	cfg.Policy.ExtensionForceAudit = false
	return cfg
}

func TestServeEnterprisePolicy_UnsealedHasNoEnterprisePlane(t *testing.T) {
	cfg := relaxedExtensionConfig()
	configDir := sealServePolicy(t, cfg, "")

	pol, err := serveEnterprisePolicy(newTestServeCmd(), cfg, configDir, discardLogger())
	require.NoError(t, err)
	require.Nil(t, pol, "personal mode applies no enterprise overrides")
}

// TestServeEnterprisePolicy_SealedWithoutPINAppliesTheDefaults is the
// fail-closed leg for a daemon with no SO at the keyboard: the sealed file is
// not read, and the secure defaults apply in its place.
func TestServeEnterprisePolicy_SealedWithoutPINAppliesTheDefaults(t *testing.T) {
	cfg := relaxedExtensionConfig()
	configDir := sealServePolicy(t, cfg, testSOPIN)

	pol, err := serveEnterprisePolicy(newTestServeCmd(), cfg, configDir, discardLogger())
	require.NoError(t, err)
	require.NotNil(t, pol)
	require.Equal(t, config.DefaultPolicy(), pol)
	require.True(t, pol.ExtensionRequireAuthentication, "the relaxed file value must not be consumed")
	require.True(t, pol.ExtensionForceAudit)
}

// TestServeEnterprisePolicy_SealedAndVerifiedIsHonouredPermissively is the
// working path in the direction the old code could not be trusted with.
func TestServeEnterprisePolicy_SealedAndVerifiedIsHonouredPermissively(t *testing.T) {
	cfg := relaxedExtensionConfig()
	configDir := sealServePolicy(t, cfg, testSOPIN)
	cmd := newTestServeCmd()
	require.NoError(t, cmd.Flags().Set(soPINFlagStdin, "true"))
	stubStdin(t, []byte(testSOPIN+"\n"), nil)

	pol, err := serveEnterprisePolicy(cmd, cfg, configDir, discardLogger())
	require.NoError(t, err)
	require.NotNil(t, pol)
	require.False(t, pol.ExtensionRequireAuthentication, "a verified relaxed value is honoured")
	require.False(t, pol.ExtensionForceAudit)
}

// TestServeEnterprisePolicy_SealedTamperedPermissivelyRefusesToStart is the
// refusal path: the SO sealed the defaults, a local user relaxed the file,
// and the server must not start under it.
func TestServeEnterprisePolicy_SealedTamperedPermissivelyRefusesToStart(t *testing.T) {
	sealed := config.DefaultConfig()
	configDir := sealServePolicy(t, sealed, testSOPIN)
	cmd := newTestServeCmd()
	t.Setenv(soPINEnvVar, testSOPIN)

	tampered := relaxedExtensionConfig()
	pol, err := serveEnterprisePolicy(cmd, tampered, configDir, discardLogger())

	require.Error(t, err)
	require.Nil(t, pol)
	require.ErrorIs(t, err, ErrServePolicyRefused)
	require.ErrorIs(t, err, config.ErrPolicyUnverifiable)
	require.ErrorIs(t, err, config.ErrPolicyHMACMismatch)
}

func TestServeEnterprisePolicy_SealedWithWrongPINRefusesToStart(t *testing.T) {
	cfg := relaxedExtensionConfig()
	configDir := sealServePolicy(t, cfg, testSOPIN)
	cmd := newTestServeCmd()
	t.Setenv(soPINEnvVar, "not-the-so-pin")

	pol, err := serveEnterprisePolicy(cmd, cfg, configDir, discardLogger())
	require.Error(t, err)
	require.Nil(t, pol)
	require.ErrorIs(t, err, ErrServePolicyRefused)
}

func TestServeEnterprisePolicy_EmptyStdinIsReported(t *testing.T) {
	cfg := relaxedExtensionConfig()
	configDir := sealServePolicy(t, cfg, testSOPIN)
	cmd := newTestServeCmd()
	require.NoError(t, cmd.Flags().Set(soPINFlagStdin, "true"))
	stubStdin(t, []byte(""), nil)

	pol, err := serveEnterprisePolicy(cmd, cfg, configDir, discardLogger())
	require.Error(t, err)
	require.Nil(t, pol)
	require.ErrorIs(t, err, ErrSOPINInputStdinEmpty)
}
