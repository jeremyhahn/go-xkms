// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

package storage_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Row 2252 (ruling 814): a key write the store has acknowledged must
// survive SIGKILL of the process in standalone mode. The test re-execs its
// own binary as a child that opens the standalone store, writes a key,
// prints "acked" and blocks; the parent kills it with SIGKILL, reopens the
// store and reads the key back.

const (
	sigkillChildEnv   = "XKMS_SIGKILL_DURABILITY_CHILD"
	sigkillPathEnv    = "XKMS_SIGKILL_DURABILITY_PATH"
	sigkillBackendEnv = "XKMS_SIGKILL_DURABILITY_BACKEND"
	sigkillKeyName    = "keys/sigkill-durability/ed25519"
)

var sigkillBackends = map[string]func(string) (storage.Backend, error){
	"file":   storage.NewFile,
	"pebble": storage.NewPebble,
}

// TestMain lets the re-exec'd child run its role and exit before any test.
func TestMain(m *testing.M) {
	if os.Getenv(sigkillChildEnv) == "1" {
		os.Exit(sigkillChild())
	}
	os.Exit(m.Run())
}

// sigkillChild writes one public key, reports it as acked and blocks until
// it is killed.
func sigkillChild() int {
	open := sigkillBackends[os.Getenv(sigkillBackendEnv)]
	if open == nil {
		fmt.Fprintln(os.Stderr, "unknown backend")
		return 2
	}
	store, err := open(os.Getenv(sigkillPathEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		return 2
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 2
	}
	if err := store.Put(context.Background(), sigkillKeyName, pub); err != nil {
		fmt.Fprintln(os.Stderr, "put:", err)
		return 2
	}
	fmt.Printf("acked %s\n", hex.EncodeToString(pub))
	select {}
}

func TestStandaloneSIGKILLKeepsAckedKey(t *testing.T) {
	for name, open := range sigkillBackends {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store")
			want := runSIGKILLChild(t, name, path)

			store, err := open(path)
			if err != nil {
				t.Fatalf("reopen %s store after SIGKILL: %v", name, err)
			}
			got, err := store.Get(context.Background(), sigkillKeyName)
			if err != nil {
				t.Fatalf("acknowledged key lost after SIGKILL (%s): %v", name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("public key after SIGKILL = %x, want %x", got, want)
			}
		})
	}
}

// runSIGKILLChild starts the child, waits for "acked", kills it with
// SIGKILL and returns the public key it acknowledged.
func runSIGKILLChild(t *testing.T, backend, path string) []byte {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		sigkillChildEnv+"=1",
		sigkillPathEnv+"="+path,
		sigkillBackendEnv+"="+backend,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "acked ") {
				lines <- strings.TrimPrefix(sc.Text(), "acked ")
				return
			}
		}
		close(lines)
	}()

	var ackedHex string
	select {
	case line, ok := <-lines:
		if !ok {
			_ = cmd.Wait()
			t.Fatalf("child exited before acking: %s", stderr.String())
		}
		ackedHex = line
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("child did not ack within 60s: %s", stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL child: %v", err)
	}
	_ = cmd.Wait()

	want, err := hex.DecodeString(ackedHex)
	if err != nil {
		t.Fatalf("decode acked key: %v", err)
	}
	return want
}
