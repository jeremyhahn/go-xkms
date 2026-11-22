//go:build unix

package audit

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// writerLock is an exclusive advisory flock(2) on a file beside the audit
// chain. flock locks belong to the open file description, so a second open
// conflicts whether it comes from this process or another one.
type writerLock struct {
	f *os.File
}

func acquireWriterLock(path string) (*writerLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open writer lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAuditWriterLocked
		}
		return nil, fmt.Errorf("audit: lock %s: %w", path, err)
	}
	return &writerLock{f: f}, nil
}

func (l *writerLock) release() error {
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return errors.Join(err, l.f.Close())
}
