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
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTPMSRKEnrollNoInlinePINFlag is ruling 994: no flag of `tpm srk
// enroll` or `fido2` takes a PIN value on the command line; the only
// PIN-carrying string flags are file paths.
func TestTPMSRKEnrollNoInlinePINFlag(t *testing.T) {
	enroll, _, err := newTPMSRKCmd().Find([]string{"enroll"})
	require.NoError(t, err)

	for _, c := range []*cobra.Command{enroll, fido2Cmd} {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			switch f.Name {
			case "pin", "so-pin", "user-pin":
				assert.Equal(t, "bool", f.Value.Type(), "%s --%s must not take a value", c.Name(), f.Name)
			}
		})
	}
	for _, name := range []string{pinFlagFile, pinFlagStdin, soPINFlagFile, soPINFlagStdin} {
		assert.NotNil(t, enroll.Flags().Lookup(name), "enroll --%s", name)
	}
	for _, name := range []string{pinFlagFile, pinFlagStdin} {
		assert.NotNil(t, fido2Cmd.Flags().Lookup(name), "fido2 --%s", name)
	}
}

// TestPINSourceFileFirstLine reads only the first line of a PIN file and
// trims its newline.
func TestPINSourceFileFirstLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(path, []byte("test-pin-a\r\nsecond-line\n"), 0o600))

	secret, err := userPINSource.secretFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, "test-pin-a", string(secret))
}

// TestPINSourceFileEmpty refuses an empty first line and a missing file,
// without naming a value.
func TestPINSourceFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(path, []byte("\n"), 0o600))

	_, err := userPINSource.secretFromFile(path)
	require.ErrorIs(t, err, ErrPINInputFileEmpty)

	_, err = userPINSource.secretFromFile(filepath.Join(t.TempDir(), "missing"))
	require.ErrorIs(t, err, ErrPINInputFileRead)
}

// TestTPMSRKEnrollNoPINNonInteractive fails with ErrTPMSRKNoPIN when no PIN
// source is given and stdin is not a terminal.
func TestTPMSRKEnrollNoPINNonInteractive(t *testing.T) {
	t.Setenv(pinEnvVar, "")
	t.Setenv(soPINEnvVar, "")
	setVar(t, &pinInputIsTerminal, func() bool { return false })

	c := newTPMSRKCmd()
	c.SetArgs([]string{"enroll"})
	c.SetOut(os.Stderr)
	err := c.Execute()
	require.ErrorIs(t, err, ErrTPMSRKNoPIN)
}

// TestSRKEnrollmentLockIsExclusive proves the enrolment lock, a lock file
// beside the platform storage, admits one holder at a time: a second
// acquisition (another process, or another open in this one) blocks until
// the first is released.
func TestSRKEnrollmentLockIsExclusive(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XKEY_DATA_DIR", dataDir)

	unlock, err := lockSRKEnrollment()
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(dataDir, srkEnrollLockName))
	assert.NoDirExists(t, filepath.Join(dataDir, "tpm"),
		"the lock must not land inside the platform storage directory")

	acquired := make(chan func(), 1)
	go func() {
		second, lockErr := lockSRKEnrollment()
		if lockErr != nil {
			acquired <- nil
			return
		}
		acquired <- second
	}()

	select {
	case <-acquired:
		t.Fatal("a second holder acquired the enrolment lock while it was held")
	case <-time.After(200 * time.Millisecond):
	}

	unlock()
	select {
	case second := <-acquired:
		require.NotNil(t, second, "the second acquisition must succeed once released")
		second()
	case <-time.After(10 * time.Second):
		t.Fatal("the released enrolment lock was never acquired")
	}
}
