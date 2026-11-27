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

// verb_helpers_test.go runs a cobra verb the way an operator would, for the
// tests of every build, tagged or not.
package main

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// verbFlag is one flag assignment; a slice of them allows repeated flags.
type verbFlag struct{ name, value string }

// resetVerbFlags restores every flag of cmd to its default, emptying slice
// flags (resetCmdFlags would leave "[]" in them).
func resetVerbFlags(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			require.NoError(t, sv.Replace(nil))
		} else {
			require.NoError(t, f.Value.Set(f.DefValue))
		}
		f.Changed = false
	})
}

// runVerb runs cmd as cfg's operator with the given flags and arguments
// and returns stdout, the exit code (-1 when it never exited) and stderr.
func runVerb(t *testing.T, cfg *Config, cmd *cobra.Command, args []string, flags ...verbFlag) (string, int, string) {
	t.Helper()
	withGlobalConfig(t, cfg)
	resetVerbFlags(t, cmd)
	defer resetVerbFlags(t, cmd)
	for _, f := range flags {
		require.NoError(t, cmd.Flags().Set(f.name, f.value))
	}
	saved := cmd.Context()
	cmd.SetContext(context.Background())
	defer cmd.SetContext(saved)

	code := -1
	var stderr string
	stdout := captureStdout(t, func() {
		code, stderr = runKeyExt(t, func() { cmd.Run(cmd, args) })
	})
	return stdout, code, stderr
}

// withSecretStdin substitutes the stdin the secret resolvers read.
func withSecretStdin(t *testing.T, content string) {
	t.Helper()
	original := secretStdin
	secretStdin = strings.NewReader(content)
	t.Cleanup(func() { secretStdin = original })
}
