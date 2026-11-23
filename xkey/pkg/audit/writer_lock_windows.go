//go:build windows

package audit

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// writerLock is an exclusive LockFileEx byte-range lock on a file beside the
// audit chain. The lock belongs to the file handle, so a second open conflicts
// whether it comes from this process or another one, and Windows releases it
// when the holding process exits or is killed: a lock file left on disk after
// a crash does not keep the chain locked.
type writerLock struct {
	f *os.File
}

func acquireWriterLock(path string) (*writerLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open writer lock %s: %w", path, err)
	}
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrAuditWriterLocked
		}
		return nil, fmt.Errorf("audit: lock %s: %w", path, err)
	}
	return &writerLock{f: f}, nil
}

func (l *writerLock) release() error {
	err := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, new(windows.Overlapped))
	return errors.Join(err, l.f.Close())
}
