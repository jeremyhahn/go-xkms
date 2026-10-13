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
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A background refresher recorded in its PID file is sent SIGTERM, and its
// PID file is removed once it has been stopped.
func TestStopProcess_TerminatesRunningRefresher(t *testing.T) {
	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		if child.ProcessState != nil {
			return
		}
		if err := child.Process.Kill(); err != nil {
			t.Logf("kill refresher: %v", err)
		}
		if err := child.Wait(); err != nil {
			t.Logf("reap refresher: %v", err)
		}
	})

	pidFile := filepath.Join(t.TempDir(), "refresh.pid")
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)+"\n"), 0o600))

	var buf bytes.Buffer
	require.NoError(t, stopProcess(&buf, pidFile, "corp"))

	assert.Contains(t, buf.String(), "Stopped background refresh for 'corp' (PID "+strconv.Itoa(child.Process.Pid)+")")
	assert.NoFileExists(t, pidFile)

	waitErr := child.Wait()
	var exitErr *exec.ExitError
	require.True(t, errors.As(waitErr, &exitErr), "the refresher must have been signalled, got %v", waitErr)
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	assert.Equal(t, syscall.SIGTERM, status.Signal())
}

func TestStopProcess_GarbagePIDFileIsNotRunning(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "refresh.pid")
	require.NoError(t, os.WriteFile(pidFile, []byte("not-a-pid"), 0o600))

	var buf bytes.Buffer
	err := stopProcess(&buf, pidFile, "corp")
	require.ErrorContains(t, err, "no running process for 'corp'")
	assert.NoFileExists(t, pidFile)
	assert.Empty(t, buf.String())
}
