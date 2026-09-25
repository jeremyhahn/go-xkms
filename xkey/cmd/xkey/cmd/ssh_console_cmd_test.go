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
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func sshConsoleTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("key", "", "")
	cmd.Flags().String("key-scope", "user", "")
	cmd.Flags().String("key-owner", "", "")
	cmd.Flags().Int("port", 0, "")
	cmd.Flags().String("user", "", "")
	cmd.Flags().Bool("local", false, "")
	cmd.Flags().String("identity", "", "")
	return cmd
}

func TestRunSSHConsole_EmptyTarget(t *testing.T) {
	err := runSSHConsole(sshConsoleTestCmd(), []string{"   "})
	require.ErrorIs(t, err, ErrSSHConnectTarget)
}

// fakeConsole is a minimal, in-memory sshsdk.ConsoleSession: Read reports
// EOF immediately, and every other method is a no-op success. It lets
// runConsoleSession's stdin/stdout pump and cleanup logic run to completion
// without any real network or PTY. CloseWrite fires from the background
// stdin-copy goroutine runConsoleSession starts, so it is signalled through
// a channel rather than a plain field: the test waits on that channel
// (a real signal) instead of racing a shared counter or sleeping.
type fakeConsole struct {
	closed       atomic.Bool
	closeWriteCh chan struct{}
}

func newFakeConsole() *fakeConsole {
	return &fakeConsole{closeWriteCh: make(chan struct{}, 1)}
}

func (f *fakeConsole) Read(p []byte) (int, error)  { return 0, io.EOF }
func (f *fakeConsole) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeConsole) Close() error                { f.closed.Store(true); return nil }
func (f *fakeConsole) Resize(rows, cols int) error { return nil }
func (f *fakeConsole) CloseWrite() error {
	select {
	case f.closeWriteCh <- struct{}{}:
	default:
	}
	return nil
}

// TestRunConsoleSession_EOFBothWays drives the whole bridge with an already
// exhausted local stdin and a console that reports EOF on its first Read: both
// io.Copy pumps return immediately, so this never blocks on a real terminal,
// process, or network connection.
func TestRunConsoleSession_EOFBothWays(t *testing.T) {
	pipeStdin(t, "")

	fd := int(os.Stdin.Fd())
	cons := newFakeConsole()

	err := runConsoleSession(cons, fd)
	require.NoError(t, err)
	require.True(t, cons.closed.Load(), "runConsoleSession must always close the session")

	// The stdin->console copy goroutine calls CloseWrite once it observes
	// EOF on the (already exhausted) stdin pipe; runConsoleSession itself
	// returns as soon as the console->stdout copy sees EOF, without waiting
	// on that goroutine, so this is a genuine async signal, not a race.
	select {
	case <-cons.closeWriteCh:
	case <-time.After(2 * time.Second):
		t.Fatal("an exhausted stdin must half-close the remote write side")
	}
}
