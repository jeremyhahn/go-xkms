//go:build unix || windows

package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The writer lock is an OS lock the kernel drops when its holder dies: a
// lock file a crashed writer left on disk does not refuse the next writer.
func TestWriterLock_LeftoverLockFileDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.lock")
	require.NoError(t, os.WriteFile(path, nil, 0o600), "lock file left by a crashed writer")

	l, err := acquireWriterLock(path)
	require.NoError(t, err, "a leftover lock file with no holder is free")
	_, err = acquireWriterLock(path)
	require.ErrorIs(t, err, ErrAuditWriterLocked, "a live holder still refuses a second writer")
	require.NoError(t, l.release())

	l, err = acquireWriterLock(path)
	require.NoError(t, err, "the lock is free after release")
	require.NoError(t, l.release())
}
