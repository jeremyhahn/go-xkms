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

package tpmdev

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsHardware(t *testing.T) {
	for _, path := range []string{"/dev/tpm0", "/dev/tpmrm0", "/dev/tpm12", "/dev/./tpmrm0"} {
		assert.True(t, IsHardware(path), path)
	}
	for _, path := range []string{"", "/dev/tpm", "/dev/tpmrm", "/tmp/swtpm.sock", "/dev/null", "tcp://localhost:2321", "/dev/tpm0x"} {
		assert.False(t, IsHardware(path), path)
	}
}

func TestIsHardware_FollowsSymlinks(t *testing.T) {
	link := filepath.Join(t.TempDir(), "my-tpm")
	require.NoError(t, os.Symlink("/dev/tpmrm0", link))
	if _, err := filepath.EvalSymlinks(link); err != nil {
		// The host has no /dev/tpmrm0 to resolve to: the alias cannot reach a
		// TPM there, and Open's own open fails.
		assert.False(t, IsHardware(link))
		return
	}
	assert.True(t, IsHardware(link), "an alias of the host TPM is the host TPM")
}

// TestOpen_RefusesTheHostTPMInTests proves a test binary never reaches the
// host's TPM by default. The refusal comes before any open, so this test
// touches no device even on a host that has one.
func TestOpen_RefusesTheHostTPMInTests(t *testing.T) {
	t.Setenv(EnvTestHardwareTPM, "")
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		f, err := Open(path)
		assert.ErrorIs(t, err, ErrHardwareTPMInTest, path)
		assert.Nil(t, f)
	}
}

func TestAllowed_OptIn(t *testing.T) {
	t.Setenv(EnvTestHardwareTPM, "1")
	assert.NoError(t, Allowed("/dev/tpmrm0"), "an explicit opt-in reaches the hardware TPM")
	t.Setenv(EnvTestHardwareTPM, "yes")
	assert.ErrorIs(t, Allowed("/dev/tpmrm0"), ErrHardwareTPMInTest, "only the exact opt-in counts")
}

func TestOpen_NonHardwarePathsOpen(t *testing.T) {
	t.Setenv(EnvTestHardwareTPM, "")
	path := filepath.Join(t.TempDir(), "not-a-tpm")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	f, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = Open(filepath.Join(t.TempDir(), "missing"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestDecide pins the rule for both kinds of process: a production process
// (not a test, no deny flag) reaches its TPM; a process under test does not
// unless it opts in.
func TestDecide(t *testing.T) {
	t.Setenv(EnvTestHardwareTPM, "")
	assert.NoError(t, decide("/dev/tpmrm0", false), "a production process uses its TPM")
	assert.ErrorIs(t, decide("/dev/tpmrm0", true), ErrHardwareTPMInTest)
	assert.NoError(t, decide("/tmp/swtpm.sock", true), "a socket is not the host TPM")

	t.Setenv(EnvTestHardwareTPM, "1")
	assert.NoError(t, decide("/dev/tpmrm0", true), "the opt-in reaches the host TPM")
}

// TestEnvDenies proves the flag the test targets export holds a process (a
// binary a test runs as a subprocess, which is not a test binary) to the
// test rule.
func TestEnvDenies(t *testing.T) {
	t.Setenv(EnvDenyHardwareTPM, "1")
	assert.True(t, envDenies())
	t.Setenv(EnvDenyHardwareTPM, "")
	assert.False(t, envDenies())
	t.Setenv(EnvDenyHardwareTPM, "true")
	assert.False(t, envDenies(), "only the exact value counts")
}
