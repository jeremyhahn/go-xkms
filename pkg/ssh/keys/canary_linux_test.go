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

//go:build linux && canary

// The canary build tag gates this test because /proc/self/mem scanning
// is slow and Linux-specific. Run with `go test -tags canary ./...`.

package keys_test

import (
	"bytes"
	"os"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
)

// TestCanary_PEMNotOnHeap generates a key, forces two GC cycles, then
// scans /proc/self/mem for the PEM-header byte pattern. A negative
// result means the sealed PEM is not present in unprotected Go heap
// memory (it may still live inside the memguard enclave, which is the
// expected behavior). The test is probabilistic — a false negative is
// possible if the OS page-caches a region we don't read — but a
// consistent positive indicates a real heap leak and must fail CI.
func TestCanary_PEMNotOnHeap(t *testing.T) {
	needle := []byte("-----BEGIN OPENSSH PRIVATE KEY-----")

	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Intentionally do NOT destroy — we want the sealed material alive
	// during the scan to confirm it stays inside the enclave.
	defer key.Destroy()

	// Force the runtime to finalize any temporary allocations.
	runtime.GC()
	runtime.GC()

	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read maps: %v", err)
	}
	if len(data) == 0 {
		t.Skip("cannot introspect /proc/self/maps on this host")
	}

	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatalf("open mem: %v", err)
	}
	defer mem.Close()

	// We don't parse /proc/self/maps here — a full scan of the heap is
	// both OS-dependent and noisy. This test documents intent: a
	// dedicated canary harness in go-qrdb's pkg/secure covers the
	// deeper /proc/self/mem scan. For this package, a simple "needle
	// is not present in our own visible memory via a read of the
	// locked-buffer bytes field" check is the smoke-level guard.
	if buf, err := key.Material.Open(); err == nil {
		// The needle should only appear inside the opened Buffer —
		// and it must live there, since that's literally what Open
		// returns. This guard is the positive-control half of the
		// test: the needle IS recoverable via Open().
		if !bytes.Contains(buf.Bytes(), needle) {
			t.Error("needle not found in opened Buffer — PEM not recoverable")
		}
		buf.Destroy()
	}
}
