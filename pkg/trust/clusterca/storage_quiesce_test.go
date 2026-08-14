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

package clusterca

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// nodeLocalDataDir returns a directory suitable for StrategyDeps.NodeLocalDataDir
// (or NodeLocalBackendsParams.DataDir) whose teardown is sequenced ahead of
// t.TempDir's own removal.
//
// Why this exists: storage.NewFile persists asynchronously. go-qrdb's
// FastStateMachine spawns a goroutine per Put, and closing the xkms storage
// Backend does not drain them — Backend.Close bottoms out in the embedded
// transport's Close, which only flips a flag and never reaches the state
// machine's wait group. A write issued shortly before Close can therefore touch
// the data directory after Close has returned.
//
// When that directory is a bare t.TempDir(), the straggling write races the
// framework's RemoveAll and the test dies during cleanup with
// "TempDir RemoveAll cleanup: directory not empty" — a failure that has nothing
// to do with the behaviour under test. Routing the directory through this
// helper absorbs the straggler in a cleanup that is allowed to wait for it.
func nodeLocalDataDir(t *testing.T) string {
	t.Helper()

	// t.TempDir registers its own cleanup here, before ours below. Cleanups run
	// last-registered-first, so removeWhenQuiescent always runs before the
	// framework's RemoveAll and leaves nothing for it to trip over.
	dir := filepath.Join(t.TempDir(), "cluster-ca")
	require.NoError(t, os.MkdirAll(dir, 0o700))

	t.Cleanup(func() { removeWhenQuiescent(t, dir) })

	return dir
}

// removeWhenQuiescent deletes dir and then confirms it stays deleted, retrying
// until the asynchronous storage writes have drained.
//
// This is deliberately self-verifying rather than a blind sleep: it fails the
// test if the directory keeps reappearing past the deadline, which would mean a
// storage goroutine is genuinely stuck rather than merely slow.
func removeWhenQuiescent(t *testing.T, dir string) {
	t.Helper()

	const (
		settle  = 10 * time.Millisecond
		timeout = 15 * time.Second
	)

	deadline := time.Now().Add(timeout)
	for {
		removeErr := os.RemoveAll(dir)

		if removeErr == nil {
			// A late write recreates the tree; require two consecutive
			// observations of "gone" before declaring the writes drained.
			time.Sleep(settle)
			if _, statErr := os.Stat(dir); errors.Is(statErr, fs.ErrNotExist) {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("node-local data dir %s never quiesced after %s "+
				"(last remove error: %v); an async storage write appears stuck",
				dir, timeout, removeErr)
		}

		time.Sleep(settle)
	}
}
