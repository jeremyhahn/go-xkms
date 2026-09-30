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

package module

import (
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/stretchr/testify/require"
)

// crossProcessAttemptDirEnv and crossProcessAttemptCountEnv drive the
// re-exec'd worker below: the directory of the shared file token, and how
// many failed attempts this worker process charges against it. Set (to a
// non-empty directory) is what tells a re-exec'd worker to run
// runFailedAttemptCrossProcessWorker and exit, rather than the top-level
// orchestration in
// TestModuleStorage_FailedAttemptCounter_CrossProcessAccumulates -- the same
// pattern pkg/crypto/fips uses to run code under a distinct process state.
const (
	crossProcessAttemptDirEnv   = "XKMS_PKCS11_CROSSPROC_DIR"
	crossProcessAttemptCountEnv = "XKMS_PKCS11_CROSSPROC_COUNT"
	crossProcessAttemptLimitEnv = "XKMS_PKCS11_CROSSPROC_LIMIT"
)

// TestModuleStorage_FailedAttemptCounter_CrossProcessAccumulates is the
// multi-process counterpart to
// TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates: several OS
// processes -- not goroutines sharing one backend -- each open their own
// ModuleStorage over one StorageTypeFile token directory and spend failed
// attempts concurrently, modeling several module instances (e.g. two
// application processes) sharing one PKCS#11 file token.
//
// This is #1157's regression test: before the fix, two processes'
// SpendFailedAttempt calls could interleave their read-compare-write on the
// shared counter file (pkg/storage/file delegated to pkg/storage/engine.go's
// engineBackend, whose CAS guard was serialized only in-process) and both
// report success, undercounting the lockout budget CKR_PIN_LOCKED depends on
// (#1144) -- a lost failed-attempt charge that lets an attacker spread guesses
// across processes to outrun the limit.
func TestModuleStorage_FailedAttemptCounter_CrossProcessAccumulates(t *testing.T) {
	if dir := os.Getenv(crossProcessAttemptDirEnv); dir != "" {
		runFailedAttemptCrossProcessWorker(t, dir)
		return
	}

	dir := t.TempDir()
	const workers = 4
	const perWorker = 20
	const limit = workers * perWorker // set above the total so every spend is admitted

	type outcome struct {
		out []byte
		err error
	}
	results := make([]outcome, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestModuleStorage_FailedAttemptCounter_CrossProcessAccumulates$", "-test.v")
			cmd.Env = append(os.Environ(),
				crossProcessAttemptDirEnv+"="+dir,
				crossProcessAttemptCountEnv+"="+strconv.Itoa(perWorker),
				crossProcessAttemptLimitEnv+"="+strconv.Itoa(limit),
			)
			out, err := cmd.CombinedOutput()
			results[i] = outcome{out: out, err: err}
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		require.NoErrorf(t, r.err, "worker %d failed:\n%s", i, r.out)
		require.Containsf(t, string(r.out), "PASS", "worker %d did not pass:\n%s", i, r.out)
	}

	backend, err := file.New(dir)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	s := NewModuleStorage(backend)
	user, _, err := s.LoadFailedAttempts(0)
	require.NoError(t, err)
	require.Equalf(t, uint32(limit), user,
		"every concurrent spend across %d processes must be counted; a lower total is a lost update (#1157)", workers)
}

// runFailedAttemptCrossProcessWorker is the child-process body: it opens its
// own ModuleStorage (fresh backend, fresh engine, fresh file lock) over the
// shared token directory and spends its share of failed attempts, requiring
// each one to be admitted -- the shared limit is set by the parent above the
// combined total, so a refusal here can only mean the durable counter is
// running ahead of what this process itself charged, i.e. lost track of who
// already spent what.
func runFailedAttemptCrossProcessWorker(t *testing.T, dir string) {
	t.Helper()
	count, err := strconv.Atoi(os.Getenv(crossProcessAttemptCountEnv))
	require.NoError(t, err)
	limit, err := strconv.Atoi(os.Getenv(crossProcessAttemptLimitEnv))
	require.NoError(t, err)

	backend, err := file.New(dir)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	s := NewModuleStorage(backend)
	for i := 0; i < count; i++ {
		_, admitted, err := s.SpendFailedAttempt(0, CKU_USER, uint32(limit))
		require.NoError(t, err)
		require.Truef(t, admitted, "spend %d of %d must be admitted: limit is set above the combined total", i, count)
	}
}
