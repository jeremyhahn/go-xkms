package cmd

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
)

// The command tests below wait on events, never on the wall clock: a slow
// runner (or a slow storage sync) only makes them take longer, and
// `go test -timeout` is the one guard against a hang.

// eventLog is a goroutine-safe io.Writer that records everything written to
// it and closes reached the first time the log satisfies want.
type eventLog struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	want    func(log string) bool
	reached chan struct{}
	once    sync.Once
}

// newEventLog returns an eventLog whose reached channel closes once want
// reports true for the log written so far. A nil want never fires.
func newEventLog(want func(log string) bool) *eventLog {
	return &eventLog{want: want, reached: make(chan struct{})}
}

func (l *eventLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.buf.Write(p)
	if l.want != nil && l.want(l.buf.String()) {
		l.once.Do(func() { close(l.reached) })
	}
	return n, err
}

func (l *eventLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// completeLineWithPrefix returns the first fully written line of log (one
// ended by a newline) that starts with prefix.
func completeLineWithPrefix(log, prefix string) (string, bool) {
	lines := strings.Split(log, "\n")
	for _, line := range lines[:len(lines)-1] {
		if strings.HasPrefix(line, prefix) {
			return line, true
		}
	}
	return "", false
}

// eventCounter closes reached on its target-th Add, for httptest handlers
// whose calls a test waits for.
type eventCounter struct {
	n       atomic.Int64
	target  int64
	reached chan struct{}
}

func newEventCounter(target int64) *eventCounter {
	return &eventCounter{target: target, reached: make(chan struct{})}
}

// Add counts one event and returns the new count.
func (c *eventCounter) Add() int64 {
	n := c.n.Add(1)
	if n == c.target {
		close(c.reached)
	}
	return n
}
