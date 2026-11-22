//go:build !unix

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// writerLock on platforms without flock(2): the lock file is created
// exclusively and removed on release, and an in-process registry refuses a
// second holder in this process. A lock file left by a crashed process
// keeps the chain locked until it is removed.
type writerLock struct {
	path string
}

var (
	writerLocksMu sync.Mutex
	writerLocks   = map[string]bool{}
)

func acquireWriterLock(path string) (*writerLock, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("audit: writer lock path %s: %w", path, err)
	}
	writerLocksMu.Lock()
	defer writerLocksMu.Unlock()
	if writerLocks[abs] {
		return nil, ErrAuditWriterLocked
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, ErrAuditWriterLocked
		}
		return nil, fmt.Errorf("audit: create writer lock %s: %w", abs, err)
	}
	_ = f.Close()
	writerLocks[abs] = true
	return &writerLock{path: abs}, nil
}

func (l *writerLock) release() error {
	writerLocksMu.Lock()
	defer writerLocksMu.Unlock()
	delete(writerLocks, l.path)
	return os.Remove(l.path)
}
