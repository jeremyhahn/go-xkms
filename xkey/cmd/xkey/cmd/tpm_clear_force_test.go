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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withEUID makes the root-only commands see euid for the duration of the
// test.
func withEUID(t *testing.T, euid int) {
	t.Helper()
	previous := geteuid
	geteuid = func() int { return euid }
	t.Cleanup(func() { geteuid = previous })
}

// ppiFixture is a temporary /sys/class/tpm tree and a reboot recorder.
type ppiFixture struct {
	classDir string
	reboots  int
}

// newPPIFixture points the force clear at a temporary sysfs tree, at the
// given TPM device path, and at a reboot recorder that returns rebootErr.
func newPPIFixture(t *testing.T, device string, rebootErr error) *ppiFixture {
	t.Helper()
	withEUID(t, 0)

	fixture := &ppiFixture{classDir: t.TempDir()}
	previousDir, previousReboot := tpmSysfsClassDir, rebootSystem
	tpmSysfsClassDir = fixture.classDir
	rebootSystem = func() error {
		fixture.reboots++
		return rebootErr
	}

	savedTPM, savedClear := *tpmCfg, *clearCfg
	tpmCfg.device = device
	*clearCfg = tpmClearConfig{force: true, yes: true}

	t.Cleanup(func() {
		tpmSysfsClassDir, rebootSystem = previousDir, previousReboot
		*tpmCfg, *clearCfg = savedTPM, savedClear
	})
	return fixture
}

// addPPI creates the PPI request file for the named TPM.
func (f *ppiFixture) addPPI(t *testing.T, tpmName string) string {
	t.Helper()
	dir := filepath.Join(f.classDir, tpmName, "ppi")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	request := filepath.Join(dir, "request")
	require.NoError(t, os.WriteFile(request, nil, 0o644))
	return request
}

func runClearCmd(t *testing.T, run func(*cobra.Command) error) (string, error) {
	t.Helper()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := run(cmd)
	return out.String(), err
}

// TestRunForceTPMClear_RequestsClearOnTheDevicesTPM pins which TPM's PPI
// receives the clear request. /dev/tpmrmN used to be trimmed to "N" and
// then defaulted to tpm0, so a clear of the second TPM was scheduled on
// the first.
func TestRunForceTPMClear_RequestsClearOnTheDevicesTPM(t *testing.T) {
	tests := []struct {
		device string
		tpm    string
	}{
		{device: "/dev/tpmrm1", tpm: "tpm1"},
		{device: "/dev/tpmrm0", tpm: "tpm0"},
		{device: "/dev/tpm2", tpm: "tpm2"},
		{device: "/run/swtpm.sock", tpm: "tpm0"},
	}
	for _, tt := range tests {
		t.Run(tt.device, func(t *testing.T) {
			fixture := newPPIFixture(t, tt.device, nil)
			decoy := fixture.addPPI(t, "tpm9")
			request := fixture.addPPI(t, tt.tpm)

			out, err := runClearCmd(t, runForceTPMClear)
			require.NoError(t, err)

			written, err := os.ReadFile(request)
			require.NoError(t, err)
			assert.Equal(t, "5", string(written), "PPI operation 5 is TPM2_Clear")
			untouched, err := os.ReadFile(decoy)
			require.NoError(t, err)
			assert.Empty(t, untouched)
			assert.Equal(t, 1, fixture.reboots)
			assert.Contains(t, out, "TPM clear scheduled")
		})
	}
}

func TestRunForceTPMClear_RequiresRoot(t *testing.T) {
	fixture := newPPIFixture(t, "/dev/tpmrm0", nil)
	request := fixture.addPPI(t, "tpm0")
	withEUID(t, 1000)

	out, err := runClearCmd(t, runForceTPMClear)
	require.ErrorIs(t, err, ErrTPMClearNotRoot)
	assert.Contains(t, out, "sudo xkey tpm clear --force")

	written, readErr := os.ReadFile(request)
	require.NoError(t, readErr)
	assert.Empty(t, written)
	assert.Zero(t, fixture.reboots)
}

func TestRunForceTPMClear_NoPPIInterface(t *testing.T) {
	fixture := newPPIFixture(t, "/dev/tpmrm0", nil)

	out, err := runClearCmd(t, runForceTPMClear)
	require.ErrorIs(t, err, ErrTPMClearPPINotFound)
	assert.Contains(t, out, filepath.Join(fixture.classDir, "tpm0", "ppi", "request"))
	assert.Zero(t, fixture.reboots)
}

func TestRunForceTPMClear_PPIWriteFailsDoesNotReboot(t *testing.T) {
	fixture := newPPIFixture(t, "/dev/tpmrm0", nil)
	// A directory where the request file belongs: it exists, but cannot
	// be written.
	require.NoError(t, os.MkdirAll(filepath.Join(fixture.classDir, "tpm0", "ppi", "request"), 0o755))

	_, err := runClearCmd(t, runForceTPMClear)
	require.ErrorIs(t, err, ErrTPMClearPPIFailed)
	assert.Zero(t, fixture.reboots)
}

func TestRunForceTPMClear_RebootFailureTellsTheOperator(t *testing.T) {
	fixture := newPPIFixture(t, "/dev/tpmrm0", errors.New("operation not permitted"))
	request := fixture.addPPI(t, "tpm0")

	out, err := runClearCmd(t, runForceTPMClear)
	require.ErrorIs(t, err, ErrTPMClearRebootFailed)
	assert.Contains(t, out, "reboot manually")

	written, readErr := os.ReadFile(request)
	require.NoError(t, readErr)
	assert.Equal(t, "5", string(written), "the clear stays scheduled for the manual reboot")
}

// TestRunTPMClear_ForceConfirmedThenRebootsAfterEnter drives the command
// entry point: the typed confirmation, then the Enter before the reboot.
func TestRunTPMClear_ForceConfirmedThenRebootsAfterEnter(t *testing.T) {
	fixture := newPPIFixture(t, "/dev/tpmrm0", nil)
	request := fixture.addPPI(t, "tpm0")
	clearCfg.yes = false
	pipeStdin(t, "yes\n\n")

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	require.NoError(t, runTPMClear(cmd, nil))

	assert.Contains(t, out.String(), "Mode: FORCE")
	assert.Contains(t, out.String(), "Press Enter to reboot")
	written, err := os.ReadFile(request)
	require.NoError(t, err)
	assert.Equal(t, "5", string(written))
	assert.Equal(t, 1, fixture.reboots)
}

func TestRunTPMClear_ForceNotConfirmedTouchesNothing(t *testing.T) {
	fixture := newPPIFixture(t, "/dev/tpmrm0", nil)
	request := fixture.addPPI(t, "tpm0")
	clearCfg.yes = false
	pipeStdin(t, "no\n")

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	require.ErrorIs(t, runTPMClear(cmd, nil), ErrTPMClearCancelled)

	written, err := os.ReadFile(request)
	require.NoError(t, err)
	assert.Empty(t, written)
	assert.Zero(t, fixture.reboots)
}
