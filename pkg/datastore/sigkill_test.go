// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//go:build linux

package datastore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// Row 2252 (ruling 814): every write a standalone node acknowledges must
// survive SIGKILL. pkg/storage's guard covers the newEmbedded stack; this
// one drives the go-qrdb node xkmsd and the SDK run in standalone mode
// (embeddednode.OpenEmbeddedNode), its default database and two of its
// named databases. The test re-execs its own binary as a child that opens
// the datastore, writes one value per database, prints an "acked" line for
// each and blocks; the parent kills it with SIGKILL, reopens the datastore
// on the same directory and reads every value back.

const (
	nodeSIGKILLChildEnv = "XKMS_NODE_SIGKILL_CHILD"
	nodeSIGKILLPathEnv  = "XKMS_NODE_SIGKILL_PATH"
	nodeSIGKILLKey      = "keys/sigkill-durability/ed25519"
	nodeSIGKILLDefault  = "default"
)

// nodeSIGKILLDatabases are the databases the child writes, in order.
var nodeSIGKILLDatabases = []string{nodeSIGKILLDefault, "keyversion", "aeadnonce"}

// TestMain lets the re-exec'd child run its role and exit before any test.
func TestMain(m *testing.M) {
	if os.Getenv(nodeSIGKILLChildEnv) == "1" {
		os.Exit(nodeSIGKILLChild())
	}
	os.Exit(m.Run())
}

func nodeSIGKILLConfig(path string) *config.Config {
	return &config.Config{
		Datastore: config.DatastoreConfig{Engine: "pebble", Path: path},
	}
}

// nodeSIGKILLPut writes value under the test key in the named database
// (the default database through the node client's KV plane).
func nodeSIGKILLPut(ctx context.Context, ds *Datastore, database string, value []byte) error {
	if database == nodeSIGKILLDefault {
		callCtx, err := ds.callContext(ctx)
		if err != nil {
			return err
		}
		return ds.Client().KV().Put(callCtx, nodeSIGKILLKey, value)
	}
	kv, err := ds.DatabaseKVStore(ctx, database)
	if err != nil {
		return err
	}
	return kv.Put(ctx, nodeSIGKILLKey, value)
}

// nodeSIGKILLGet reads the test key back from the named database.
func nodeSIGKILLGet(ctx context.Context, ds *Datastore, database string) ([]byte, error) {
	if database == nodeSIGKILLDefault {
		callCtx, err := ds.callContext(ctx)
		if err != nil {
			return nil, err
		}
		return ds.Client().KV().Get(callCtx, nodeSIGKILLKey)
	}
	kv, err := ds.DatabaseKVStore(ctx, database)
	if err != nil {
		return nil, err
	}
	return kv.Get(ctx, nodeSIGKILLKey)
}

// nodeSIGKILLChild writes one fresh public key per database, reports each
// as acked and blocks until it is killed.
func nodeSIGKILLChild() int {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ds, err := Open(ctx, nodeSIGKILLConfig(os.Getenv(nodeSIGKILLPathEnv)), logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		return 2
	}
	for _, database := range nodeSIGKILLDatabases {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "keygen:", err)
			return 2
		}
		if err := nodeSIGKILLPut(ctx, ds, database, pub); err != nil {
			fmt.Fprintf(os.Stderr, "put %s: %v\n", database, err)
			return 2
		}
		fmt.Printf("acked %s %s\n", database, hex.EncodeToString(pub))
	}
	select {}
}

func TestStandaloneNodeSIGKILLKeepsAckedWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node")
	want := runNodeSIGKILLChild(t, path)

	ds, err := Open(t.Context(), nodeSIGKILLConfig(path), testLogger())
	if err != nil {
		t.Fatalf("reopen standalone datastore after SIGKILL: %v", err)
	}
	t.Cleanup(func() {
		if err := ds.Close(); err != nil {
			t.Errorf("close datastore: %v", err)
		}
	})

	for _, database := range nodeSIGKILLDatabases {
		got, err := nodeSIGKILLGet(t.Context(), ds, database)
		if err != nil {
			t.Errorf("acknowledged write to %s lost after SIGKILL: %v", database, err)
			continue
		}
		if !bytes.Equal(got, want[database]) {
			t.Errorf("%s value after SIGKILL = %x, want %x", database, got, want[database])
		}
	}
}

// runNodeSIGKILLChild starts the child, waits for an "acked" line per
// database, kills it with SIGKILL and returns the acknowledged values.
func runNodeSIGKILLChild(t *testing.T, path string) map[string][]byte {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		nodeSIGKILLChildEnv+"=1",
		nodeSIGKILLPathEnv+"="+path,
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

	lines := make(chan string, len(nodeSIGKILLDatabases))
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if rest, ok := strings.CutPrefix(sc.Text(), "acked "); ok {
				lines <- rest
			}
		}
	}()

	acked := make(map[string][]byte, len(nodeSIGKILLDatabases))
	deadline := time.After(60 * time.Second)
	for len(acked) < len(nodeSIGKILLDatabases) {
		select {
		case line, ok := <-lines:
			if !ok {
				_ = cmd.Wait()
				t.Fatalf("child exited after %d acks: %s", len(acked), stderr.String())
			}
			database, hexValue, found := strings.Cut(line, " ")
			if !found {
				t.Fatalf("malformed acked line %q", line)
			}
			value, err := hex.DecodeString(hexValue)
			if err != nil {
				t.Fatalf("decode acked value for %s: %v", database, err)
			}
			acked[database] = value
		case <-deadline:
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("child acked %d of %d writes within 60s: %s",
				len(acked), len(nodeSIGKILLDatabases), stderr.String())
		}
	}

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL child: %v", err)
	}
	_ = cmd.Wait()
	return acked
}
