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
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPINCommand builds a command carrying the PIN flags, as every command that
// resolves a PIN must.
func newPINCommand(t *testing.T) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	addPINFlags(cmd)
	return cmd
}

// stubStdin points the shared stdin reader at fixed bytes for one test.
func stubStdin(t *testing.T, data []byte, err error) {
	t.Helper()

	original := stdinReader
	stdinReader = func() ([]byte, error) { return data, err }
	t.Cleanup(func() { stdinReader = original })
}

// TestAddPINFlagsDeclaresStdinSource proves the helper declares exactly the
// flag the resolver reads, and that it declares no value flag: a "--pin"
// value on the command line was removed (go-xkms#272) because it is visible
// to every other process on the host via 'ps'.
func TestAddPINFlagsDeclaresStdinSource(t *testing.T) {
	cmd := newPINCommand(t)

	require.NotNil(t, cmd.Flags().Lookup(pinFlagStdin), "--pin-stdin must be declared")
	require.Nil(t, cmd.Flags().Lookup("pin"), "a --pin value flag must not be declared")

	pin, err := resolvePINInput(cmd)
	require.NoError(t, err)
	assert.Empty(t, pin, "a command with no PIN supplied resolves to none")
}

func TestResolvePINInputPrecedence(t *testing.T) {
	t.Run("stdin outranks the environment", func(t *testing.T) {
		t.Setenv(pinEnvVar, "from-env")
		stubStdin(t, []byte("from-stdin\n"), nil)

		cmd := newPINCommand(t)
		require.NoError(t, cmd.Flags().Set(pinFlagStdin, "true"))

		pin, err := resolvePINInput(cmd)
		require.NoError(t, err)
		assert.Equal(t, "from-stdin", pin, "the trailing newline must be trimmed")
	})

	t.Run("the environment is the last resort", func(t *testing.T) {
		t.Setenv(pinEnvVar, "from-env")

		pin, err := resolvePINInput(newPINCommand(t))
		require.NoError(t, err)
		assert.Equal(t, "from-env", pin)
	})

	t.Run("a carriage return pair is trimmed too", func(t *testing.T) {
		t.Setenv(pinEnvVar, "")
		stubStdin(t, []byte("123456\r\n"), nil)

		cmd := newPINCommand(t)
		require.NoError(t, cmd.Flags().Set(pinFlagStdin, "true"))

		pin, err := resolvePINInput(cmd)
		require.NoError(t, err)
		assert.Equal(t, "123456", pin)
	})

	t.Run("no source supplied resolves to no PIN, not an error", func(t *testing.T) {
		// An authenticator with no PIN configured needs none, so the resolver
		// must not impose a policy its callers do not share.
		t.Setenv(pinEnvVar, "")

		pin, err := resolvePINInput(newPINCommand(t))
		require.NoError(t, err)
		assert.Empty(t, pin)
	})
}

func TestResolvePINInputErrors(t *testing.T) {
	t.Run("--pin-stdin with nothing on stdin is an error, not an empty PIN", func(t *testing.T) {
		// Silently continuing here is what made the original defect illegible:
		// the ceremony failed inside the authenticator with a CTAP error that
		// named neither the PIN nor the flag.
		t.Setenv(pinEnvVar, "from-env")
		stubStdin(t, []byte("\n"), nil)

		cmd := newPINCommand(t)
		require.NoError(t, cmd.Flags().Set(pinFlagStdin, "true"))

		pin, err := resolvePINInput(cmd)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPINInputStdinEmpty)
		assert.Empty(t, pin)
	})

	t.Run("an unreadable stdin is reported", func(t *testing.T) {
		readErr := errors.New("read: broken pipe")
		stubStdin(t, nil, readErr)

		cmd := newPINCommand(t)
		require.NoError(t, cmd.Flags().Set(pinFlagStdin, "true"))

		_, err := resolvePINInput(cmd)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPINInputStdinRead)
		assert.ErrorIs(t, err, readErr, "the cause must survive for diagnosis")
	})

	t.Run("a command that declares no PIN flags is a wiring defect", func(t *testing.T) {
		// Reported rather than swallowed: a command silently resolving no PIN
		// looks to the operator exactly like an authenticator that needs none.
		_, err := resolvePINInput(&cobra.Command{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPINInputFlagsMissing)
	})
}

// TestResolveUnlockPINAppliesItsOwnPolicy proves unlock keeps its stricter
// contract on top of the shared resolver: unlocking without a PIN is
// meaningless, so an absent PIN is an error there even though the resolver
// treats it as legitimate.
func TestResolveUnlockPINAppliesItsOwnPolicy(t *testing.T) {
	t.Run("a supplied PIN passes through", func(t *testing.T) {
		t.Setenv(pinEnvVar, "123456")

		pin, err := resolveUnlockPIN(newPINCommand(t))
		require.NoError(t, err)
		assert.Equal(t, "123456", pin)
	})

	t.Run("an absent PIN is rejected", func(t *testing.T) {
		t.Setenv(pinEnvVar, "")

		_, err := resolveUnlockPIN(newPINCommand(t))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnlockMissingPIN)
	})

	t.Run("a resolver error is not converted into a missing PIN", func(t *testing.T) {
		stubStdin(t, nil, errors.New("read: broken pipe"))

		cmd := newPINCommand(t)
		require.NoError(t, cmd.Flags().Set(pinFlagStdin, "true"))

		_, err := resolveUnlockPIN(cmd)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPINInputStdinRead)
		assert.NotErrorIs(t, err, ErrUnlockMissingPIN,
			"an unreadable stdin is a different problem from no PIN supplied")
	})
}
