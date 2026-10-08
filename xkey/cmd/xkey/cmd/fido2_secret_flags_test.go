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

// Tests for the two "xkey fido2" flags that carry secret material:
// --barrier-password-stdin and --set-pin-stdin. Both replaced a
// "--barrier-password"/"--set-pin" value flag (go-xkms#1209): a value on the
// command line is visible to every other process on the host via 'ps'.

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFIDO2SecretViperKeys clears the viper keys resolveFIDO2BarrierPassword
// and resolveFIDO2SetPINSecret read, so one test's value cannot leak into the
// next: viper is process-global state, unlike a *cobra.Command's own flags.
func resetFIDO2SecretViperKeys(t *testing.T) {
	t.Helper()
	viper.Set("fido2.barrier_password_stdin", false)
	viper.Set("fido2.set_pin_stdin", false)
	t.Cleanup(func() {
		viper.Set("fido2.barrier_password_stdin", false)
		viper.Set("fido2.set_pin_stdin", false)
	})
}

// TestFIDO2Cmd_NoBarrierPasswordValueFlag pins go-xkms#1209: "xkey fido2"
// does not accept the barrier password as a flag value.
func TestFIDO2Cmd_NoBarrierPasswordValueFlag(t *testing.T) {
	assert.Nil(t, fido2Cmd.Flags().Lookup("barrier-password"), "--barrier-password value flag must not exist")
	assert.NotNil(t, fido2Cmd.Flags().Lookup("barrier-password-stdin"), "--barrier-password-stdin flag must exist")
	assert.NotNil(t, fido2Cmd.Flags().Lookup("barrier-password-file"), "--barrier-password-file flag must exist")
}

// TestFIDO2Cmd_NoSetPINValueFlag pins go-xkms#1209: "xkey fido2" does not
// accept the initial PIN to establish as a flag value.
func TestFIDO2Cmd_NoSetPINValueFlag(t *testing.T) {
	assert.Nil(t, fido2Cmd.Flags().Lookup("set-pin"), "--set-pin value flag must not exist")
	assert.NotNil(t, fido2Cmd.Flags().Lookup("set-pin-stdin"), "--set-pin-stdin flag must exist")
}

// TestResolveFIDO2BarrierPassword_Stdin pins the stdin source.
func TestResolveFIDO2BarrierPassword_Stdin(t *testing.T) {
	resetFIDO2SecretViperKeys(t)
	stubStdin(t, []byte("stdin-barrier-pw\n"), nil)
	viper.Set("fido2.barrier_password_stdin", true)

	got := resolveFIDO2BarrierPassword()
	assert.Equal(t, "stdin-barrier-pw", got)
}

// TestResolveFIDO2BarrierPassword_None pins that no source configured
// resolves to "", the historical "no barrier password" contract
// createBarrierStorage relies on to fall through to XKEY_BARRIER_PASSWORD or
// --barrier-password-file.
func TestResolveFIDO2BarrierPassword_None(t *testing.T) {
	resetFIDO2SecretViperKeys(t)
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	assert.Empty(t, resolveFIDO2BarrierPassword())
}

// TestResolveFIDO2BarrierPassword_Env pins the environment source used when
// --barrier-password-stdin was not given.
func TestResolveFIDO2BarrierPassword_Env(t *testing.T) {
	resetFIDO2SecretViperKeys(t)
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-barrier-pw")

	assert.Equal(t, "env-barrier-pw", resolveFIDO2BarrierPassword())
}

// TestResolveFIDO2SetPINSecret_Stdin pins the stdin source for the initial
// PIN to establish.
func TestResolveFIDO2SetPINSecret_Stdin(t *testing.T) {
	resetFIDO2SecretViperKeys(t)
	stubStdin(t, []byte("123456\n"), nil)
	viper.Set("fido2.set_pin_stdin", true)

	secret := resolveFIDO2SetPINSecret()
	require.NotNil(t, secret)
	defer secret.Destroy()

	buf, err := secret.Open(t.Context())
	require.NoError(t, err)
	defer buf.Destroy()
	require.NoError(t, buf.WithBytes(func(b []byte) error {
		assert.Equal(t, "123456", string(b))
		return nil
	}))
}

// TestResolveFIDO2SetPINSecret_NotProvided pins that --set-pin-stdin absent
// resolves to nil: no --set-pin was provided, matching fido2PINSecret's
// historical contract. There is no environment variable for this flag (see
// fido2SetPINSource's doc comment).
func TestResolveFIDO2SetPINSecret_NotProvided(t *testing.T) {
	resetFIDO2SecretViperKeys(t)

	assert.Nil(t, resolveFIDO2SetPINSecret())
}
