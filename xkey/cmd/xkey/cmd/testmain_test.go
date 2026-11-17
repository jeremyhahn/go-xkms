package cmd

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
// runners with a deep TMPDIR (#2248).
func TestMain(m *testing.M) { os.Exit(shortTMPDIR(m.Run)) }

// shortTMPDIR is internal/testtmp.Short for this module, which requires a
// go-xkms release without that package. It makes one short directory
// (/tmp/xkNNNN, or under os.TempDir() when /tmp is unusable), sets TMPDIR to
// it while run executes, then restores TMPDIR and removes the directory. It
// returns run's exit code.
func shortTMPDIR(run func() int) int {
	dir, err := mkdirShortTMPDIR("/tmp")
	if err != nil {
		dir, err = os.MkdirTemp(os.TempDir(), "xk")
		if err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: creating a short temporary directory: %v\n", err)
			return run()
		}
	}

	prev, had := os.LookupEnv("TMPDIR")
	if err := os.Setenv("TMPDIR", dir); err != nil {
		fmt.Fprintf(os.Stderr, "shortTMPDIR: setting TMPDIR: %v\n", err)
	}
	defer func() {
		if had {
			_ = os.Setenv("TMPDIR", prev)
		} else {
			_ = os.Unsetenv("TMPDIR")
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: removing %s: %v\n", dir, err)
		}
	}()

	return run()
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
