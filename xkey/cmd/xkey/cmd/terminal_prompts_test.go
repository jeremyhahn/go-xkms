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
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// openTerminal makes the slave side of a new pseudo-terminal os.Stdin,
// opened with flag, and returns the master side.
func openTerminal(t *testing.T, flag int) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = master.Close() })
	require.NoError(t, unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0))
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	require.NoError(t, err)

	slave, err := os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(n)), flag|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	previous := os.Stdin
	os.Stdin = slave
	t.Cleanup(func() {
		os.Stdin = previous
		_ = slave.Close()
	})
	return master
}

// typeAtTerminal puts stdin on a terminal and types input into it, the way
// a user answers the prompts.
func typeAtTerminal(t *testing.T, input string) {
	t.Helper()
	master := openTerminal(t, os.O_RDWR)
	_, err := master.WriteString(input)
	require.NoError(t, err)
}

// unreadableTerminal puts stdin on a terminal that cannot be read: it is a
// terminal to every check, but reading a password from it fails.
func unreadableTerminal(t *testing.T) {
	t.Helper()
	openTerminal(t, os.O_WRONLY)
}

func TestReadAndConfirmPassphrase_Terminal(t *testing.T) {
	t.Run("confirmed", func(t *testing.T) {
		typeAtTerminal(t, "storage-pass\nstorage-pass\n")
		var out bytes.Buffer
		got, err := readAndConfirmPassphrase(&out)
		require.NoError(t, err)
		assert.Equal(t, "storage-pass", got)
		assert.Contains(t, out.String(), "Enter passphrase for encrypted storage: ")
		assert.Contains(t, out.String(), "Confirm passphrase: ")
		assert.NotContains(t, out.String(), "storage-pass", "the passphrase is never echoed")
	})

	t.Run("mismatch", func(t *testing.T) {
		typeAtTerminal(t, "storage-pass\nother\n")
		_, err := readAndConfirmPassphrase(&bytes.Buffer{})
		require.ErrorIs(t, err, luks.ErrPassphraseMismatch)
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, err := readAndConfirmPassphrase(&bytes.Buffer{})
		var sealErr *SealError
		require.ErrorAs(t, err, &sealErr)
		assert.Equal(t, "read_passphrase", sealErr.Operation)
	})
}

func TestReadMigratePassphrases_Terminal(t *testing.T) {
	t.Run("new passphrase", func(t *testing.T) {
		typeAtTerminal(t, "old-pass\nnew-pass\nnew-pass\n")
		var out bytes.Buffer
		oldPass, newPass, err := readMigratePassphrases(&out)
		require.NoError(t, err)
		assert.Equal(t, "old-pass", oldPass)
		assert.Equal(t, "new-pass", newPass)
		assert.Contains(t, out.String(), "Confirm new passphrase: ")
	})

	t.Run("enter keeps the same passphrase", func(t *testing.T) {
		typeAtTerminal(t, "old-pass\n\n")
		var out bytes.Buffer
		oldPass, newPass, err := readMigratePassphrases(&out)
		require.NoError(t, err)
		assert.Equal(t, "old-pass", oldPass)
		assert.Equal(t, "old-pass", newPass)
		assert.NotContains(t, out.String(), "Confirm new passphrase", "reusing the passphrase needs no confirmation")
	})

	t.Run("mismatch", func(t *testing.T) {
		typeAtTerminal(t, "old-pass\nnew-pass\nother\n")
		_, _, err := readMigratePassphrases(&bytes.Buffer{})
		require.ErrorIs(t, err, luks.ErrPassphraseMismatch)
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, _, err := readMigratePassphrases(&bytes.Buffer{})
		var migrateErr *MigrateError
		require.ErrorAs(t, err, &migrateErr)
		assert.Equal(t, "read_passphrase", migrateErr.Operation)
		require.ErrorIs(t, err, ErrMigratePassphraseRead)
	})
}

func TestReadAndConfirmBarrierPassword_Terminal(t *testing.T) {
	t.Run("confirmed", func(t *testing.T) {
		typeAtTerminal(t, "barrier-pw\nbarrier-pw\n")
		var out bytes.Buffer
		got, err := readAndConfirmBarrierPassword(&out)
		require.NoError(t, err)
		assert.Equal(t, "barrier-pw", got)
		assert.Contains(t, out.String(), "Confirm password: ")
	})

	t.Run("mismatch", func(t *testing.T) {
		typeAtTerminal(t, "barrier-pw\nother\n")
		_, err := readAndConfirmBarrierPassword(&bytes.Buffer{})
		require.ErrorIs(t, err, ErrBarrierPasswordConfirm)
	})

	t.Run("empty", func(t *testing.T) {
		typeAtTerminal(t, "\n\n")
		_, err := readAndConfirmBarrierPassword(&bytes.Buffer{})
		require.ErrorIs(t, err, ErrBarrierPasswordEmpty)
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, err := readAndConfirmBarrierPassword(&bytes.Buffer{})
		var barrierErr *BarrierError
		require.ErrorAs(t, err, &barrierErr)
		assert.Equal(t, "read_password", barrierErr.Operation)
	})
}

func TestReadBarrierPassword_Terminal(t *testing.T) {
	t.Run("entered", func(t *testing.T) {
		typeAtTerminal(t, "barrier-pw\n")
		var out bytes.Buffer
		got, err := readBarrierPassword(&out, "Barrier password: ")
		require.NoError(t, err)
		assert.Equal(t, "barrier-pw", got)
		assert.Contains(t, out.String(), "Barrier password: ")
	})

	t.Run("empty", func(t *testing.T) {
		typeAtTerminal(t, "\n")
		_, err := readBarrierPassword(&bytes.Buffer{}, "Barrier password: ")
		require.ErrorIs(t, err, ErrBarrierPasswordEmpty)
	})
}

func TestReadAndConfirmPIN_Terminal(t *testing.T) {
	t.Run("confirmed", func(t *testing.T) {
		typeAtTerminal(t, "123456\n123456\n")
		var out bytes.Buffer
		got, err := readAndConfirmPIN(&out, "New PIN: ")
		require.NoError(t, err)
		assert.Equal(t, "123456", got)
		assert.Contains(t, out.String(), "New PIN: ")
		assert.Contains(t, out.String(), "Confirm PIN: ")
	})

	t.Run("mismatch", func(t *testing.T) {
		typeAtTerminal(t, "123456\n654321\n")
		_, err := readAndConfirmPIN(&bytes.Buffer{}, "New PIN: ")
		require.ErrorIs(t, err, ErrPINCmdMismatch)
	})

	t.Run("empty", func(t *testing.T) {
		typeAtTerminal(t, "\n\n")
		_, err := readAndConfirmPIN(&bytes.Buffer{}, "New PIN: ")
		require.ErrorIs(t, err, ErrPINCmdEmpty)
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, err := readAndConfirmPIN(&bytes.Buffer{}, "New PIN: ")
		var pinErr *PINCommandError
		require.ErrorAs(t, err, &pinErr)
		assert.Equal(t, "read_pin", pinErr.Operation)
	})
}

func TestReadPIN_Terminal(t *testing.T) {
	t.Run("entered", func(t *testing.T) {
		typeAtTerminal(t, "123456\n")
		got, err := readPIN(&bytes.Buffer{}, "PIN: ")
		require.NoError(t, err)
		assert.Equal(t, "123456", got)
	})

	t.Run("empty", func(t *testing.T) {
		typeAtTerminal(t, "\n")
		_, err := readPIN(&bytes.Buffer{}, "PIN: ")
		require.ErrorIs(t, err, ErrPINCmdEmpty)
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, err := readPIN(&bytes.Buffer{}, "PIN: ")
		var pinErr *PINCommandError
		require.ErrorAs(t, err, &pinErr)
		assert.Equal(t, "read_pin", pinErr.Operation)
	})
}

func TestReadUSBPassphrase_Terminal(t *testing.T) {
	newCmd := func(t *testing.T) (*cobra.Command, *bytes.Buffer) {
		cmd := &cobra.Command{}
		cmd.SetContext(t.Context())
		var out bytes.Buffer
		cmd.SetOut(&out)
		return cmd, &out
	}

	t.Run("confirmed", func(t *testing.T) {
		typeAtTerminal(t, "usb-pass\nusb-pass\n")
		cmd, out := newCmd(t)
		secret, err := readUSBPassphrase(cmd)
		require.NoError(t, err)
		defer secret.Destroy()
		assert.Equal(t, "usb-pass", openSecretString(t, secret))
		assert.Contains(t, out.String(), "Enter passphrase for LUKS data partition: ")
	})

	tests := []struct {
		name      string
		typed     string
		operation string
	}{
		{name: "mismatch", typed: "usb-pass\nother\n", operation: "confirm_passphrase"},
		{name: "empty", typed: "\n\n", operation: "validate_passphrase"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typeAtTerminal(t, tt.typed)
			cmd, _ := newCmd(t)
			secret, err := readUSBPassphrase(cmd)
			assert.Nil(t, secret)
			requireUSBCmdError(t, err, tt.operation)
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		cmd, _ := newCmd(t)
		secret, err := readUSBPassphrase(cmd)
		assert.Nil(t, secret)
		requireUSBCmdError(t, err, "read_passphrase")
	})
}

func TestReadImportPassphrase_Terminal(t *testing.T) {
	t.Run("entered", func(t *testing.T) {
		typeAtTerminal(t, "luks-pass\n")
		var out bytes.Buffer
		got, err := readImportPassphrase(&out)
		require.NoError(t, err)
		assert.Equal(t, "luks-pass", got)
		assert.Contains(t, out.String(), "Enter passphrase for LUKS volume: ")
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, err := readImportPassphrase(&bytes.Buffer{})
		var importErr *ImportDataError
		require.ErrorAs(t, err, &importErr)
		assert.Equal(t, "read_passphrase", importErr.Operation)
	})
}

func TestReadUnsealPassphrase_Terminal(t *testing.T) {
	t.Run("entered", func(t *testing.T) {
		typeAtTerminal(t, "luks-pass\n")
		var out bytes.Buffer
		got, err := readUnsealPassphrase(&out)
		require.NoError(t, err)
		assert.Equal(t, "luks-pass", got)
		assert.Contains(t, out.String(), "Enter passphrase: ")
	})

	t.Run("unreadable", func(t *testing.T) {
		unreadableTerminal(t)
		_, err := readUnsealPassphrase(&bytes.Buffer{})
		var unsealErr *UnsealError
		require.ErrorAs(t, err, &unsealErr)
		assert.Equal(t, "read_passphrase", unsealErr.Operation)
	})
}
