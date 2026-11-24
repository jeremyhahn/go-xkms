package ssh

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
// runners with a deep TMPDIR or GOTMPDIR (#2248).
func TestMain(m *testing.M) { os.Exit(shortTMPDIR(m.Run)) }

// shortTMPDIR is go-xkms internal/testsupport.RunWithShortTempDir for this module, which pins a
// go-xkms release without that package. It makes one short directory
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

	// t.TempDir() makes its directories under GOTMPDIR when it is set
	// (testing.go: os.MkdirTemp(os.Getenv("GOTMPDIR"), ...)), so both
	// variables point at the short directory.
	restore := setShortEnv(map[string]string{"TMPDIR": dir, "GOTMPDIR": dir})
	defer func() {
		restore()
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: removing %s: %v\n", dir, err)
		}
	}()

	return run()
}

// setShortEnv sets each variable in vars and returns a func that restores the
// previous values (unsetting those that were unset).
func setShortEnv(vars map[string]string) func() {
	type saved struct {
		val string
		had bool
	}
	prev := make(map[string]saved, len(vars))
	for k, v := range vars {
		old, had := os.LookupEnv(k)
		prev[k] = saved{old, had}
		if err := os.Setenv(k, v); err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: setting %s: %v\n", k, err)
		}
	}
	return func() {
		for k, s := range prev {
			if s.had {
				_ = os.Setenv(k, s.val)
			} else {
				_ = os.Unsetenv(k)
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
