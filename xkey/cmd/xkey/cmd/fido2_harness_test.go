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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/test/integration/logins"
)

// The logins integration harness execs the built xkey binary with a fixed
// argv (test/integration/logins.VirtualAuthenticatorArgv) to start the
// virtual authenticator. Cobra parses that argv at daemon start, so a flag
// removed from the fido2 command turns the whole suite dark at runtime, and
// CI never sees it because the suite only runs inside the devcontainer
// (#409: --auto-uv, removed by #365, was still exec'd). These tests resolve
// the harness argv against the real command tree at unit-test time instead.

var (
	errHarnessArgvSubcommand  = errors.New("harness argv does not resolve to the fido2 command")
	errHarnessArgvPositional  = errors.New("harness argv carries a positional argument")
	errHarnessArgvUnknownFlag = errors.New("harness argv uses a flag the fido2 command does not register")
	errHarnessArgvValue       = errors.New("harness argv flag value is not accepted")
)

// checkHarnessArgv resolves argv the way the xkey binary would: the leading
// words must select the fido2 command, every remaining word must be a
// registered flag, and every value must be one the flag accepts. Values are
// validated against the live flag and restored, so the package-level
// fido2Cmd other tests read is left unchanged.
func checkHarnessArgv(root *cobra.Command, argv []string) error {
	target, rest, err := root.Find(argv)
	if err != nil {
		return fmt.Errorf("%w: %v", errHarnessArgvSubcommand, err)
	}
	if target != fido2Cmd {
		return fmt.Errorf("%w: resolved to %q", errHarnessArgvSubcommand, target.CommandPath())
	}
	for _, arg := range rest {
		name, isFlag := strings.CutPrefix(arg, "--")
		if !isFlag {
			return fmt.Errorf("%w: %q", errHarnessArgvPositional, arg)
		}
		name, value, hasValue := strings.Cut(name, "=")
		flag := target.Flag(name)
		if flag == nil {
			return fmt.Errorf("%w: --%s", errHarnessArgvUnknownFlag, name)
		}
		if !hasValue {
			if flag.NoOptDefVal == "" {
				return fmt.Errorf("%w: --%s needs a value", errHarnessArgvValue, name)
			}
			continue
		}
		if err := checkFlagValue(flag, value); err != nil {
			return err
		}
	}
	return nil
}

// checkFlagValue sets value on flag to prove the flag accepts it, then
// restores the previous value so the check has no lasting effect.
func checkFlagValue(flag *pflag.Flag, value string) error {
	previous := flag.Value.String()
	if err := flag.Value.Set(value); err != nil {
		return fmt.Errorf("%w: --%s=%q: %v", errHarnessArgvValue, flag.Name, value, err)
	}
	if err := flag.Value.Set(previous); err != nil {
		return fmt.Errorf("%w: restoring --%s=%q: %v", errHarnessArgvValue, flag.Name, previous, err)
	}
	return nil
}

// TestFIDO2Cmd_HarnessArgvIsRegistered is the fail-fast guard #409 asks
// for: the argv the logins harness execs must be accepted by the fido2
// command as it is built today. It goes red when a flag the harness relies
// on is removed or renamed, before anyone starts the devcontainer.
func TestFIDO2Cmd_HarnessArgvIsRegistered(t *testing.T) {
	require.NoError(t, checkHarnessArgv(RootCmd, logins.VirtualAuthenticatorArgv))
}

// TestFIDO2Cmd_HarnessArgvLeavesFlagsUntouched proves the value check
// restores the live flags, so this guard cannot leak state into the other
// tests that read fido2Cmd's flag values.
func TestFIDO2Cmd_HarnessArgvLeavesFlagsUntouched(t *testing.T) {
	// fido2Cmd.Flags() only returns what cobra has already merged into
	// fido2Cmd's own FlagSet: its locally declared flags plus, once
	// something has resolved a command through fido2Cmd (root.Find below,
	// ParseFlags, ...), every ancestor's persistent flags (e.g. --log-level
	// from RootCmd). fido2Cmd is a package-level singleton shared by every
	// test in this process, so whether that merge already happened depends
	// on which other tests ran first. Resolve the harness argv once here,
	// discarding the result, so the merge is forced before the "before"
	// snapshot is taken: otherwise a not-yet-merged persistent flag is
	// absent from "before" but present (at its declared default) in
	// "after", and the comparison below reports it as changed when it
	// never was (go-xkms#1328).
	_, _, err := RootCmd.Find(logins.VirtualAuthenticatorArgv)
	require.NoError(t, err)

	before := map[string]string{}
	fido2Cmd.Flags().VisitAll(func(f *pflag.Flag) {
		before[f.Name] = f.Value.String()
	})
	require.NoError(t, checkHarnessArgv(RootCmd, logins.VirtualAuthenticatorArgv))
	fido2Cmd.Flags().VisitAll(func(f *pflag.Flag) {
		require.Equal(t, before[f.Name], f.Value.String(), "flag --%s changed", f.Name)
		require.False(t, f.Changed, "flag --%s marked changed", f.Name)
	})
}

// TestCheckHarnessArgv_RejectsWhatTheBinaryRejects walks every way the
// exec'd argv can fail at daemon start, including the exact #409 argv, and
// asserts each is reported as the typed error the failure belongs to.
func TestCheckHarnessArgv_RejectsWhatTheBinaryRejects(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want error
	}{
		{
			name: "removed --auto-uv (the #409 argv)",
			argv: []string{"fido2", "--require-touch=false", "--auto-uv", "--pin=false"},
			want: errHarnessArgvUnknownFlag,
		},
		{
			name: "renamed flag",
			argv: []string{"fido2", "--require-touch=false", "--pin-enabled=false"},
			want: errHarnessArgvUnknownFlag,
		},
		{
			name: "wrong subcommand",
			argv: []string{"touch", "--require-touch=false"},
			want: errHarnessArgvSubcommand,
		},
		{
			name: "empty argv resolves to root",
			argv: []string{},
			want: errHarnessArgvSubcommand,
		},
		{
			name: "positional argument",
			argv: []string{"fido2", "--require-touch=false", "extra"},
			want: errHarnessArgvPositional,
		},
		{
			name: "bool flag with a non-bool value",
			argv: []string{"fido2", "--pin=maybe"},
			want: errHarnessArgvValue,
		},
		{
			name: "string flag with no value",
			argv: []string{"fido2", "--storage"},
			want: errHarnessArgvValue,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHarnessArgv(RootCmd, tc.argv)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// TestCheckHarnessArgv_AcceptsBareBoolAndInheritedFlags covers the two
// argv shapes the harness does not use today but the binary accepts: a bool
// flag given without "=value", and a flag inherited from the root command.
func TestCheckHarnessArgv_AcceptsBareBoolAndInheritedFlags(t *testing.T) {
	require.NoError(t, checkHarnessArgv(RootCmd, []string{"fido2", "--require-touch", "--pin=false"}))
	require.NoError(t, checkHarnessArgv(RootCmd, []string{"fido2", "--pin=false", "--config=/dev/null"}))
	require.NoError(t, checkHarnessArgv(RootCmd, []string{"fido", "--pin=false"}), "the fido alias must resolve too")
}
