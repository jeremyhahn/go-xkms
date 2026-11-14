package authenticator

import (
	"runtime"
	"testing"
)

// TestArgon2idTestCost pins the test-only Argon2id memory cost (CA m2540).
// At the production cost every SO PIN or User PIN derivation allocates
// 64 MiB, and under -race the package's test binary was OOM-killed in an
// 8 GiB cgroup. One SO PIN Initialize (one derivation) must allocate less
// than 8 MiB in tests, while the stored parameters stay at production values.
func TestArgon2idTestCost(t *testing.T) {
	const limit = 8 << 20

	mgr := NewSOPINManager()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	smk, err := mgr.Initialize("123456")
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if len(smk) != SOPINDerivedKeySize {
		t.Fatalf("derived key length = %d, want %d", len(smk), SOPINDerivedKeySize)
	}

	if got := after.TotalAlloc - before.TotalAlloc; got >= limit {
		t.Errorf("one SO PIN derivation allocated %d bytes, want < %d", got, limit)
	}

	if mgr.Memory != SOPINDefaultMemory || mgr.Iterations != SOPINDefaultIterations ||
		mgr.Parallelism != SOPINDefaultParallelism {
		t.Errorf("stored parameters = (t=%d, m=%d, p=%d), want production (t=%d, m=%d, p=%d)",
			mgr.Iterations, mgr.Memory, mgr.Parallelism,
			SOPINDefaultIterations, SOPINDefaultMemory, SOPINDefaultParallelism)
	}
}
