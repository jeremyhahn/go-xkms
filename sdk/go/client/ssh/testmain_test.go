// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

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
// runners with a deep TMPDIR (#2248).
func TestMain(m *testing.M) { os.Exit(shortTMPDIR(m.Run)) }

// shortTMPDIR is internal/testtmp.Short for this module, which cannot import
// go-xkms's internal packages. It makes one short directory
// (/tmp/xkNNNN, or under os.TempDir() when /tmp is unusable), sets TMPDIR and\n// GOTMPDIR to it while run executes, then restores both and removes the directory. It
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

	// t.TempDir prefers GOTMPDIR over TMPDIR, so both point at dir.
	restore := make([]func(), 0, 2)
	for _, key := range []string{"TMPDIR", "GOTMPDIR"} {
		prev, had := os.LookupEnv(key)
		if err := os.Setenv(key, dir); err != nil {
			fmt.Fprintf(os.Stderr, "shortTMPDIR: setting %s: %v\n", key, err)
		}
		restore = append(restore, func() {
			if had {
				_ = os.Setenv(key, prev)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
	defer func() {
		for _, r := range restore {
			r()
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
