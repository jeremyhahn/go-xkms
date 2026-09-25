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
	"testing"

	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// TestIsStdinTTY_PipeIsNotATerminal redirects stdin to an os.Pipe -- never a
// character device -- so this exercises the "false" branch deterministically
// regardless of whether the host running the test happens to have a real
// terminal attached to its own stdin.
func TestIsStdinTTY_PipeIsNotATerminal(t *testing.T) {
	pipeStdin(t, "")
	require.False(t, isStdinTTY())
}

func TestSSHPassphraseProvider_NonTTYReturnsStdinProvider(t *testing.T) {
	pipeStdin(t, "")
	provider := sshPassphraseProvider()
	_, ok := provider.(*secure.StdinProvider)
	require.True(t, ok, "a non-interactive stdin must select the piped StdinProvider, got %T", provider)
}
