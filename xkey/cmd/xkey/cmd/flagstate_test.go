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
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// restoreFlagValue writes value back onto flag the same way pflag itself
// populated it, so a flag backed by pflag.SliceValue (StringSlice,
// StringArray, IntSlice, ...) is restored correctly.
//
// pflag.Value.Set on a slice-backed flag appends once that flag has ever
// been marked Changed, and never un-marks it: it can only replace the slice
// the first time Set is ever called on that Value in the process, because
// the append-vs-replace decision reads a private "changed" bool on the
// concrete Value, not the public pflag.Flag.Changed this package also
// tracks. Restoring such a flag with a plain Set therefore appends the
// saved snapshot onto whatever the test just set instead of replacing it,
// and the slice -- and the cost of stringifying it on every later
// snapshot -- grows without bound across every test that touches the same
// shared command tree. pflag.SliceValue.Replace bypasses that private flag
// entirely and always overwrites, which is what a restore needs (go-xkms
// #1047 follow-up).
func restoreFlagValue(flag *pflag.Flag, value flagValue) error {
	if sv, ok := flag.Value.(pflag.SliceValue); ok {
		return sv.Replace(value.slice)
	}
	return flag.Value.Set(value.scalar)
}

// flagValue captures how a flag's current contents were read, so
// restoreFlagValue can write them back through the matching path.
type flagValue struct {
	scalar string
	slice  []string
}

// captureFlagValue reads flag's current contents through whichever path
// restoreFlagValue will later write them back through.
func captureFlagValue(flag *pflag.Flag) flagValue {
	if sv, ok := flag.Value.(pflag.SliceValue); ok {
		return flagValue{slice: sv.GetSlice()}
	}
	return flagValue{scalar: flag.Value.String()}
}

// setFlagForTest sets flag name on flags to value, then restores the flag's
// prior value and Changed state once the test completes.
//
// Cobra's package-level commands (RootCmd and its subcommands) are shared
// singletons for the life of the test binary process, and many of them
// share persistent flags declared once on an ancestor (--socket, --backend,
// etc.). Calling flags.Set directly, as most of this package's tests used
// to, permanently marks the flag Changed and leaves the test's value in
// place; any later test in the same process that reads the same flag (or a
// package-level default derived from it) observes that leaked value instead
// of the flag's declared default (go-xkms#1047).
func setFlagForTest(t *testing.T, flags *pflag.FlagSet, name, value string) error {
	t.Helper()
	flag := flags.Lookup(name)
	if flag == nil {
		return fmt.Errorf("flag --%s is not declared", name)
	}
	prevValue := captureFlagValue(flag)
	prevChanged := flag.Changed
	if err := flags.Set(name, value); err != nil {
		return err
	}
	t.Cleanup(func() {
		if err := restoreFlagValue(flag, prevValue); err != nil {
			t.Errorf("restoring flag --%s: %v", name, err)
		}
		flag.Changed = prevChanged
	})
	return nil
}

// savedFlag is the pre-test state of one flag, keyed by the flag's own
// identity so a re-walk at cleanup time can tell an already-seen flag from
// one that appeared since.
type savedFlag struct {
	value   flagValue
	changed bool
}

// walkCommands calls visit for cmd and every descendant command,
// recursively.
func walkCommands(cmd *cobra.Command, visit func(*cobra.Command)) {
	visit(cmd)
	for _, child := range cmd.Commands() {
		walkCommands(child, visit)
	}
}

// walkCommandFlags calls visit for every flag reachable from cmd -- its own
// Flags()/PersistentFlags() and every descendant command's, recursively.
func walkCommandFlags(cmd *cobra.Command, visit func(*pflag.Flag)) {
	walkCommands(cmd, func(c *cobra.Command) {
		c.Flags().VisitAll(visit)
		c.PersistentFlags().VisitAll(visit)
	})
}

// resetCommandFlagsForTest snapshots the value and Changed state of every
// flag reachable from cmd and restores each one once the test completes; it
// also clears every reachable command's output/error/input redirection back
// to cobra's default of inheriting from its parent (ultimately os.Stdout/
// os.Stderr/os.Stdin).
//
// cobra.Command.Execute parses argv directly into whatever command tree cmd
// belongs to, marking every flag argv touches as Changed and leaving its
// last argv value in place. When cmd is the package-level RootCmd (shared
// for the life of the test binary), that pollutes every later test that
// reads the same flag; call this before the first SetArgs/Execute in any
// test that drives RootCmd, so its cleanup undoes exactly what that test
// did (go-xkms#1047).
//
// cobra also lazily adds some flags (--help, --version) to a command's own
// FlagSet the first time that command is executed, rather than at
// AddCommand time, so a walk taken before Execute can miss them. The
// cleanup re-walks the tree rather than replaying the original list, and
// treats any flag it did not see in the first walk as newly created by this
// test's own Execute call: it resets that flag to its declared default
// rather than a "previous" value that never existed.
//
// SetOut/SetErr/SetIn have the same shared-singleton hazard as flags: a
// test that points RootCmd.SetOut at its own buffer and forgets to put it
// back leaves every later command that inherits output from RootCmd (any
// command that never calls SetOut itself, which is most of them) silently
// writing into that buffer instead of the next test's own capture. Cobra
// has no getter for a command's raw (possibly-unset) writer, only
// OutOrStdout/OutOrStderr/InOrStdin, which resolve the inherited value and
// so cannot distinguish "unset" from "set to this". Forcing every writer
// back to nil is therefore the only reset that composes across tests: it
// restores cobra's own default of inheriting from the parent instead of
// pinning a specific writer some other test happened to be using.
func resetCommandFlagsForTest(t *testing.T, cmd *cobra.Command) {
	t.Helper()

	saved := make(map[*pflag.Flag]savedFlag)
	walkCommandFlags(cmd, func(f *pflag.Flag) {
		saved[f] = savedFlag{value: captureFlagValue(f), changed: f.Changed}
	})

	t.Cleanup(func() {
		walkCommandFlags(cmd, func(f *pflag.Flag) {
			s, ok := saved[f]
			if !ok {
				// Cobra created this flag after the snapshot above (its
				// first Execute lazily adds --help/--version); there is no
				// prior state to restore, so fall back to the flag's own
				// declared default.
				s = savedFlag{value: flagValue{scalar: f.DefValue}, changed: false}
			}
			if err := restoreFlagValue(f, s.value); err != nil {
				t.Errorf("restoring flag --%s: %v", f.Name, err)
			}
			f.Changed = s.changed
		})
		walkCommands(cmd, func(c *cobra.Command) {
			c.SetOut(nil)
			c.SetErr(nil)
			c.SetIn(nil)
		})
	})
}
