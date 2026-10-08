package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFileAtomic_WritesWithSecretMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, WriteFileAtomic(path, []byte("v1"), 0600))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "v1", string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWriteFileAtomic_FixesWiderExistingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0644))
	require.NoError(t, os.Chmod(path, 0644))

	require.NoError(t, WriteFileAtomic(path, []byte("new"), 0600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWriteFileAtomic_InterruptedWriteKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0600))

	original := renameFile
	renameFile = func(string, string) error { return errors.New("crash before rename") }
	defer func() { renameFile = original }()

	err := WriteFileAtomic(path, []byte("new"), 0600)
	require.ErrorIs(t, err, ErrWriteFile)

	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "old", string(got))

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 1, "temp file must be removed after a failure")
}

func TestWriteFileAtomic_DirSyncFailureIsTyped(t *testing.T) {
	original := syncDir
	syncDir = func(string) error { return errors.New("sync failed") }
	defer func() { syncDir = original }()

	err := WriteFileAtomic(filepath.Join(t.TempDir(), "secret"), []byte("x"), 0600)
	assert.ErrorIs(t, err, ErrWriteFile)
}

func TestWriteFileAtomic_MissingDirectoryIsTyped(t *testing.T) {
	err := WriteFileAtomic(filepath.Join(t.TempDir(), "missing", "secret"), []byte("x"), 0600)
	assert.ErrorIs(t, err, ErrWriteFile)
}

func TestWriteFileAtomic_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(victim, link))

	err := WriteFileAtomic(link, []byte("new"), 0600)
	assert.ErrorIs(t, err, ErrSymlinkTarget)

	got, readErr := os.ReadFile(victim)
	require.NoError(t, readErr)
	assert.Equal(t, "keep", string(got))
}

func TestWriteFileAtomic_RefusesDirectory(t *testing.T) {
	err := WriteFileAtomic(t.TempDir(), []byte("x"), 0600)
	assert.ErrorIs(t, err, ErrTargetNotRegular)
}

func TestCreateExclusive_CreatesWithMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, CreateExclusive(path, []byte("k"), 0600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestCreateExclusive_RefusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0600))

	err := CreateExclusive(path, []byte("new"), 0600)
	assert.ErrorIs(t, err, ErrExists)

	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "old", string(got))
}

func TestCreateExclusive_MissingDirectoryIsTyped(t *testing.T) {
	err := CreateExclusive(filepath.Join(t.TempDir(), "missing", "key"), []byte("k"), 0600)
	assert.ErrorIs(t, err, ErrWriteFile)
}

// failingFile fails on Write or Close, landing a partial write first.
type failingFile struct {
	f        *os.File
	writeErr error
	closeErr error
}

func (w *failingFile) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		_, _ = w.f.Write(p[:len(p)/2])
		return 0, w.writeErr
	}
	return w.f.Write(p)
}

func (w *failingFile) Sync() error { return w.f.Sync() }

func (w *failingFile) Close() error {
	_ = w.f.Close()
	return w.closeErr
}

func (w *failingFile) Stat() (os.FileInfo, error) { return w.f.Stat() }

func TestCreateExclusive_RemovesPartialFileOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		writeErr error
		closeErr error
	}{
		{name: "write fails", writeErr: errors.New("disk full")},
		{name: "close fails", closeErr: errors.New("flush failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")

			original := openExclusive
			openExclusive = func(p string, perm os.FileMode) (syncFile, error) {
				f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
				if err != nil {
					return nil, err
				}
				return &failingFile{f: f, writeErr: tc.writeErr, closeErr: tc.closeErr}, nil
			}
			defer func() { openExclusive = original }()

			err := CreateExclusive(path, []byte("secret-key"), 0600)
			require.ErrorIs(t, err, ErrWriteFile)

			_, statErr := os.Stat(path)
			assert.True(t, os.IsNotExist(statErr), "partial file survived: %v", statErr)
		})
	}
}

// swappingFile lands a partial write, then lets another party replace the
// path before reporting failure.
type swappingFile struct {
	f    *os.File
	path string
}

func (w *swappingFile) Write(p []byte) (int, error) {
	_, _ = w.f.Write(p[:len(p)/2])
	if err := os.Rename(w.path, w.path+".stolen"); err != nil {
		return 0, err
	}
	if err := os.WriteFile(w.path, []byte("not yours\n"), 0600); err != nil {
		return 0, err
	}
	return 0, errors.New("disk full")
}

func (w *swappingFile) Sync() error                { return w.f.Sync() }
func (w *swappingFile) Close() error               { return w.f.Close() }
func (w *swappingFile) Stat() (os.FileInfo, error) { return w.f.Stat() }

func TestCreateExclusive_DoesNotDeleteAReplacementFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")

	original := openExclusive
	openExclusive = func(p string, perm os.FileMode) (syncFile, error) {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return nil, err
		}
		return &swappingFile{f: f, path: p}, nil
	}
	defer func() { openExclusive = original }()

	require.ErrorIs(t, CreateExclusive(path, []byte("secret-key"), 0600), ErrWriteFile)

	got, err := os.ReadFile(path)
	require.NoError(t, err, "the replacement file was deleted by the cleanup")
	assert.Equal(t, "not yours\n", string(got))
}
