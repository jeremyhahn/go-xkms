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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestRunAutoBootstrapNoServerURL verifies that an empty server URL returns
// ErrBootstrapServerURLRequired.
func TestRunAutoBootstrapNoServerURL(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL:    "",
		daneHostname: "kms.example.com",
	}
	err := runAutoBootstrap(params)
	assert.ErrorIs(t, err, ErrBootstrapServerURLRequired)
}

// TestRunAutoBootstrapNoMethodsConfigured verifies that when no bootstrap
// methods are configured, ErrNoBootstrapMethodConfigured is returned.
func TestRunAutoBootstrapNoMethodsConfigured(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
		// No dane, noise, spki, or direct configured
	}
	err := runAutoBootstrap(params)
	assert.ErrorIs(t, err, ErrNoBootstrapMethodConfigured)
}

// TestRunAutoBootstrapAllMethodsFail verifies that when all configured methods
// fail, the error wraps ErrAllBootstrapMethodsFailed.
func TestRunAutoBootstrapAllMethodsFail(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://unreachable.invalid:8443",
		spkiPin:   "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	err := runAutoBootstrap(params)
	assert.ErrorIs(t, err, ErrAllBootstrapMethodsFailed)
}

// TestBuildAutoConfig_DANE verifies that DANE config is populated when
// daneHostname is set.
func TestBuildAutoConfig_DANE(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL:     "https://kms.example.com:8443",
		daneHostname:  "kms.example.com",
		daneDNSServer: "8.8.8.8:53",
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	assert.Equal(t, params.serverURL, cfg.ServerURL)
	assert.Equal(t, bootstrap.ModeAuto, cfg.Mode)
	require.NotNil(t, cfg.DANE)
	assert.Equal(t, params.daneHostname, cfg.DANE.Hostname)
	assert.Equal(t, params.daneDNSServer, cfg.DANE.DNSServer)
	assert.Nil(t, cfg.Noise)
	assert.Nil(t, cfg.SPKI)
	assert.Nil(t, cfg.Direct)
}

// TestBuildAutoConfig_Noise verifies that Noise config is populated when
// noiseKey is set. Address derivation is handled by the library at
// Fetch time (verified in pkg/trust/bootstrap tests).
func TestBuildAutoConfig_Noise(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
		noiseKey:  "0000000000000000000000000000000000000000000000000000000000000000",
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Noise)
	// CLI passes an empty ServerAddr; bootstrap library derives one
	// from cfg.ServerURL inside Fetch.
	assert.Empty(t, cfg.Noise.ServerAddr)
	assert.Equal(t, params.noiseKey, cfg.Noise.ServerStaticKey)
	assert.Nil(t, cfg.DANE)
	assert.Nil(t, cfg.SPKI)
	assert.Nil(t, cfg.Direct)
}

// TestBuildAutoConfig_P256KeyAlone verifies that the FIPS-approved suite's
// key alone configures the Noise method: a FIPS client has no Noise_NK key
// to give, and must not need one.
func TestBuildAutoConfig_P256KeyAlone(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
		p256Key:   "04" + strings.Repeat("00", 64),
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Noise)
	assert.Empty(t, cfg.Noise.ServerStaticKey)
	assert.Equal(t, params.p256Key, cfg.Noise.ServerP256StaticKey)
}

// TestBuildAutoConfig_BothNoiseKeys verifies both keys travel together, so
// the library can offer whichever suite the build runs.
func TestBuildAutoConfig_BothNoiseKeys(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
		noiseKey:  strings.Repeat("00", 32),
		p256Key:   "04" + strings.Repeat("00", 64),
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Noise)
	assert.Equal(t, params.noiseKey, cfg.Noise.ServerStaticKey)
	assert.Equal(t, params.p256Key, cfg.Noise.ServerP256StaticKey)
}

// TestBuildAutoConfig_NoiseExplicitAddr verifies that an explicit noise-addr
// is preserved on the per-mode sub-config.
func TestBuildAutoConfig_NoiseExplicitAddr(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
		noiseKey:  "0000000000000000000000000000000000000000000000000000000000000000",
		noiseAddr: "noise.example.com:9999",
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.Noise)
	assert.Equal(t, "noise.example.com:9999", cfg.Noise.ServerAddr)
}

// TestBuildAutoConfig_SPKI verifies that SPKI config is populated when
// spkiPin is set.
func TestBuildAutoConfig_SPKI(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
		spkiPin:   "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	assert.Equal(t, params.serverURL, cfg.ServerURL)
	require.NotNil(t, cfg.SPKI)
	assert.Equal(t, params.spkiPin, cfg.SPKI.Pin)
	assert.Nil(t, cfg.DANE)
	assert.Nil(t, cfg.Noise)
	assert.Nil(t, cfg.Direct)
}

// TestBuildAutoConfig_Direct verifies that Direct config is populated when
// directEnabled is true.
func TestBuildAutoConfig_Direct(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL:     "https://kms.example.com:8443",
		directEnabled: true,
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	assert.Equal(t, params.serverURL, cfg.ServerURL)
	require.NotNil(t, cfg.Direct)
	assert.Nil(t, cfg.DANE)
	assert.Nil(t, cfg.Noise)
	assert.Nil(t, cfg.SPKI)
}

// TestBuildAutoConfig_AllMethods verifies that all method configs are populated
// when all flags are set.
func TestBuildAutoConfig_AllMethods(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL:     "https://kms.example.com:8443",
		daneHostname:  "kms.example.com",
		noiseKey:      "0000000000000000000000000000000000000000000000000000000000000000",
		spkiPin:       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		directEnabled: true,
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	assert.NotNil(t, cfg.DANE)
	assert.NotNil(t, cfg.Noise)
	assert.NotNil(t, cfg.SPKI)
	assert.NotNil(t, cfg.Direct)
}

// TestBuildAutoConfig_BundlePath verifies that a custom bundle path is
// passed through on the root Config.BundlePath (every mode that consumes
// it picks it up from there inside the bootstrap library).
func TestBuildAutoConfig_BundlePath(t *testing.T) {
	customPath := "/custom/ca/endpoint"
	params := &autoBootstrapParams{
		serverURL:     "https://kms.example.com:8443",
		daneHostname:  "kms.example.com",
		spkiPin:       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		directEnabled: true,
		bundlePath:    customPath,
	}
	cfg := buildAutoConfig(params)
	require.NotNil(t, cfg)
	assert.Equal(t, customPath, cfg.BundlePath)
}

// TestBuildAutoConfig_NoneConfigured verifies that nil is returned when no
// methods are configured.
func TestBuildAutoConfig_NoneConfigured(t *testing.T) {
	params := &autoBootstrapParams{
		serverURL: "https://kms.example.com:8443",
	}
	cfg := buildAutoConfig(params)
	assert.Nil(t, cfg)
}

// Method-order behavior is now owned by the library (which always
// passes go-truststrap's DefaultMethodOrder). Coverage lives in
// pkg/trust/bootstrap. No xkmsctl-level assertion remains.

// TestWriteCABundleToFile verifies that writeCABundle writes the bundle
// to a file when an output path is specified.
func TestWriteCABundleToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "ca-bundle.pem")
	bundle := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

	// Capture stdout.
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	err := writeCABundle(bundle, outFile)
	_ = w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	// Verify file contents.
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, bundle, data)
}

// TestWriteCABundleToFileError verifies that writeCABundle returns
// ErrBootstrapBundleWrite when the file cannot be written.
func TestWriteCABundleToFileError(t *testing.T) {
	bundle := []byte("test")
	err := writeCABundle(bundle, "/nonexistent/path/ca-bundle.pem")
	assert.ErrorIs(t, err, ErrBootstrapBundleWrite)
}

// TestWriteCABundleToStdout verifies that writeCABundle writes to stdout
// when no output path is specified.
func TestWriteCABundleToStdout(t *testing.T) {
	bundle := []byte("-----BEGIN CERTIFICATE-----\nstdout-test\n-----END CERTIFICATE-----\n")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := writeCABundle(bundle, "")

	_ = w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])
	assert.Contains(t, output, "CA bundle obtained via bootstrap")
	assert.Contains(t, output, "stdout-test")
}

// Noise address derivation is canonically tested in
// pkg/trust/bootstrap/bootstrap_test.go::TestDeriveNoiseAddr.
// xkmsctl now delegates via the library so no separate
// CLI-level test is needed here.

// TestBootstrapAutoCommandFlagParsing verifies that the auto command
// correctly parses all its flags.
func TestBootstrapAutoCommandFlagParsing(t *testing.T) {
	expectedFlags := []string{
		"server-url",
		"config",
		"dane-hostname",
		"dane-dns-server",
		"noise-key",
		"p256-key",
		"noise-addr",
		"spki-pin",
		"direct",
		"bundle-path",
		"bundle-output",
	}
	for _, flagName := range expectedFlags {
		flag := bootstrapAutoCmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "flag --%s should be registered", flagName)
	}
}

// TestBootstrapAutoCommandServerURLRequired verifies that runAutoBootstrap
// returns an error when --server-url is missing.
func TestBootstrapAutoCommandServerURLRequired(t *testing.T) {
	err := runAutoBootstrap(&autoBootstrapParams{
		daneHostname: "kms.example.com",
	})
	assert.ErrorIs(t, err, ErrBootstrapServerURLRequired)
}
