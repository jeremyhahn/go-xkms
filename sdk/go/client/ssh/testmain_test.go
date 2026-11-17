package ssh_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestMain keeps t.TempDir() short so unix socket paths fit in sun_path on
// runners with a deep TMPDIR or GOTMPDIR (#2250).
func TestMain(m *testing.M) { os.Exit(shortTMPDIR(m.Run)) }

// shortTMPDIR is go-xkms internal/testtmp.Short for this module, which cannot
// import an internal package of the root module. It makes one short directory
// (/tmp/xkNNNN, or under os.TempDir() when /tmp is unusable), sets TMPDIR and
// GOTMPDIR to it while run executes, then restores both and removes the
// directory. It returns run's exit code.
func shortTMPDIR(run func() int) int {
	dir, err := mkdirShortTMPDIR("/tmp")
	if err != nil {
		dir, err = os.MkdirTemp(os.TempDir(), "xk")
		if err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: creating a short temporary directory: %v\n", err)
			return run()
		}
	}

	// t.TempDir() uses GOTMPDIR when set (src/testing/testing.go), and
	// os.TempDir() uses TMPDIR: both must point at the short directory.
	restore := setShortEnv(dir, "TMPDIR", "GOTMPDIR")
	defer func() {
		restore()
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: removing %s: %v\n", dir, err)
		}
	}()

	return run()
}

// setShortEnv sets each named variable to value and returns a func that
// restores the previous values (unsetting those that were unset).
func setShortEnv(value string, names ...string) (restore func()) {
	type saved struct {
		name, prev string
		had        bool
	}
	prevs := make([]saved, 0, len(names))
	for _, name := range names {
		prev, had := os.LookupEnv(name)
		prevs = append(prevs, saved{name: name, prev: prev, had: had})
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: setting %s: %v\n", name, err)
		}
	}
	return func() {
		for _, s := range prevs {
			if s.had {
				_ = os.Setenv(s.name, s.prev)
			} else {
				_ = os.Unsetenv(s.name)
			}
		}
	}
}

// mkdirShortTMPDIR creates root/xkNNNN with 4 random base-36 characters: 6
// bytes shorter than os.MkdirTemp's suffix, which some socket paths need.
func mkdirShortTMPDIR(root string) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	var lastErr error
	for range 1000 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		name := []byte("xk")
		for _, c := range b {
			name = append(name, alphabet[int(c)%len(alphabet)])
		}
		dir := filepath.Join(root, string(name))
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		lastErr = err
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", lastErr
}
