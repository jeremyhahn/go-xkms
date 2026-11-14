// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// bootstrap_noise_run_test.go exercises the "xkmsctl bootstrap noise" Run
// closures (generate-key, show-key, show-spki-pin), which just read flags
// and delegate to the already-tested named functions.
package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// The Run wrapper is thin, but "thin" is not "untestable": with no assertion
// at all this test passed against a no-op closure, so it could not detect the
// wrapper being disconnected from generateNoiseKey -- or from its --output
// flag, which is the one thing the wrapper is responsible for reading.
//
// It therefore asserts the command's contract end to end: the private key
// lands in the file named by --output, at 0600, hex-encoded and usable; the
// public key is printed; and the private key is NOT, which is the ruling the
// command's own help text states.
func TestNoiseGenerateKeyCmd_Run(t *testing.T) {
	cmd := noiseGenerateKeyCmd
	keyPath := filepath.Join(t.TempDir(), "noise.key")
	_ = cmd.Flags().Set("output", keyPath)

	if !noiseKeygenOutsideFIPS(t, keyPath, func() { cmd.Run(cmd, nil) }) {
		return
	}

	// Captured into protected memory, not the usual captureStdout: the case
	// this test exists to catch is the one where the command prints the
	// private key, and captureStdout would put it in a Go string, where it is
	// unwipeable. See secure_capture_test.go. The limit is generous for two
	// short lines and an over-run is an error rather than a truncation --
	// truncated output would satisfy the no-leak assertion below for free.
	stdoutBuf, stdoutLen := captureStdoutSecret(t, 32<<10, func() {
		cmd.Run(cmd, nil)
	})
	defer stdoutBuf.Destroy()

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("--output file was never created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", perm)
	}
	if info.Size() == 0 {
		t.Fatal("--output file is empty")
	}

	// From here on the file's contents are the private key, so it is read
	// straight into protected memory and never lands anywhere that cannot be
	// wiped.
	//
	// os.ReadFile is not good enough even followed by a wipe: the charter asks
	// for key material to live in protected memory, and a plain heap slice is
	// swappable and dumpable for as long as it is alive.
	keyFile, err := os.Open(keyPath)
	if err != nil {
		t.Fatalf("opening the key file: %v", err)
	}
	defer keyFile.Close()

	encBuf, encLen, err := readAllSecret(keyFile, int(info.Size()))
	if err != nil {
		t.Fatalf("reading the key file into protected memory: %v", err)
	}
	defer encBuf.Destroy()

	// Borrowed in place: the encoded key and the captured stdout are each read
	// inside their own protected buffer's borrow, never copied out of it. The
	// two are different buffers, so holding both borrows at once is safe.
	err = encBuf.WithBytes(func(enc []byte) error {
		// Trimmed as BYTES, and a sub-slice of the protected buffer rather than
		// a copy. strings.TrimSpace(string(raw)) would mint the unwipeable copy
		// this is avoiding.
		encoded := bytes.TrimSpace(enc[:encLen])

		// The key has to be the real one: decode it straight into protected
		// memory, derive its public half, and require the command to have
		// printed exactly that.
		key, err := bootstrap.DecodeNoiseStaticKey(encoded)
		if err != nil {
			t.Fatalf("the written key does not load: %v", err)
		}
		defer key.Destroy()
		if err := bootstrap.WithNoisePrivateKey(key, func(priv []byte) error {
			if len(priv) != 32 {
				t.Fatalf("private key is %d bytes, want 32", len(priv))
			}
			if allZeroBytes(priv) {
				t.Fatal("private key is all zeroes")
			}
			return nil
		}); err != nil {
			t.Fatalf("borrowing the written key: %v", err)
		}

		return stdoutBuf.WithBytes(func(out []byte) error {
			stdout := out[:stdoutLen]

			// Both checks run over stdout normalised IN PLACE, inside the
			// protected buffer it was captured into. bytes.ToLower would
			// allocate an ordinary heap copy, and on the failure path that copy
			// is where the leaked key would be.
			//
			// stdout is the output of a command under test, so on the failure
			// path it is exactly where a leaked private key would be. An
			// earlier version printed it verbatim in the failure message --
			// meaning the first regression to print the key would copy it into
			// CI output, permanently, before the no-leak assertion below ever
			// ran. A test for a leak must not be the thing that publishes it.
			//
			// So nothing here reports raw output. Failures carry lengths and a
			// yes/no, which is enough to diagnose.
			lowerASCIIInPlace(stdout)

			// The public half is not secret; it is what the command is
			// supposed to print. hex.EncodeToString already emits lowercase.
			wantPub := hex.EncodeToString(key.PublicBytes())
			if !bytes.Contains(stdout, []byte(wantPub)) {
				t.Errorf("stdout does not contain the public key derived from the written private key "+
					"(stdout was %d bytes; not printed here, it is where a leaked private key would be)",
					stdoutLen)
			}

			// The private key must never reach stdout -- terminal scrollback,
			// shell history, pipes and CI logs cannot be wiped.
			//
			// Compared as bytes against the encoded key lowercased in place in
			// its own protected buffer, rather than through
			// strings.ToLower(hexKey), which would materialise the secret as a
			// string for the sole purpose of proving it is not leaked.
			lowerASCIIInPlace(encoded)
			if bytes.Contains(stdout, encoded) {
				t.Error("the private key was printed to stdout")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("borrowing the captured output: %v", err)
	}
}

func allZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestNoiseShowKeyCmd_Run(t *testing.T) {
	cmd := noiseShowKeyCmd
	_ = cmd.Flags().Set("key-file", "")
	_ = cmd.Flags().Set("key-hex", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for no key input, got %d", code)
	}
}

func TestNoiseShowSPKIPinCmd_Run(t *testing.T) {
	cmd := noiseShowSPKIPinCmd
	_ = cmd.Flags().Set("cert-file", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for no cert-file, got %d", code)
	}
}
