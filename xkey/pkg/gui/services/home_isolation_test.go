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

package services

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// This file makes reaching the developer's real configuration a compile-and-run
// impossibility for this package rather than a convention each test is trusted
// to follow.
//
// Two things went wrong without it, both measured on main (#102):
//
//   - TestFSC_ApplySOProvisioning_EnterprisePolicyFields called config.Save()
//     with no config.SetConfigDir, so it overwrote the developer's real
//     ~/.config/xkey/xkey.yaml with defaults and then deleted it. It set
//     SetupWizardService.SetConfigDir — the OTHER of the two resolvers PR #90
//     documented — which looks like isolation and is not.
//   - TestSurgB_PhoneService_SaveConfig_NoError wrote the real
//     ~/.xkey/devices.yaml, and its "restore state" branch only removes the
//     file when it did NOT exist before. On a machine with paired devices it
//     replaces the real device list with an empty one and leaves it there.
//
// The second consequence is the order dependence #102 was filed for:
// TestP3A_PhoneService_ListDevices_NoConfigFile asserts the no-config path
// returns nothing, and read whatever devices.yaml the machine — or an earlier
// test in the same run — had left behind. It passed on a fresh CI runner for
// the wrong reason, and failed on a workstation for a reason that had nothing
// to do with its subject.

// processHomeDir is the sealed home every test in this package sees unless it
// asks for its own with isolateHome. Nothing may be written under it; see
// processHomeLeaks.
var processHomeDir string

// processConfigDir is the config directory config.ConfigDir resolves to while
// no test holds an isolateHome override. It sits inside processHomeDir and is
// therefore unwritable, which is what isolateHome restores to.
var processConfigDir string

// TestMain points every home-derived path this package resolves at runtime —
// $HOME, the XDG bases, and pkg/config's own override — at a process-scoped
// temporary directory, makes it READ-ONLY, and asserts after the suite that
// nothing was written there anyway.
//
// Stopping the write is the load-bearing part. Redirecting alone protects the
// developer's files but leaves the tests sharing one directory, so a test that
// writes there still decides what a later test reads: the order dependence
// survives the fix that was supposed to remove it. Unwritable, a test that
// reaches shared state fails at the write, naming itself, instead of silently
// seeding a neighbour. Isolation stops being a convention a new test can
// forget and becomes a precondition it cannot get around.
//
// It is enforced TWICE because neither mechanism alone covers both machines:
//
//   - The mode bits stop the write where it happens, with the failing test
//     named — but they do not constrain root, and the CI runner executes as
//     root (measured: GOCACHE=/root/.cache/go-build). For uid 0 the seal
//     silently degrades to a plain redirect while still reading as enforced.
//   - assertProcessHomeUntouched runs after m.Run and fails the suite if
//     anything appeared under the process home. That holds for every uid. It
//     reports later and less precisely than the mode bits, which is why both
//     are here rather than only this one.
//
// Making the path a regular file instead would block root too, and was tried:
// it turns a legitimate "no config, use defaults" read into ENOTDIR, which
// pkg/config does not classify as absent, and 12 tests that correctly exercise
// the no-config path failed. A guard that changes what absent MEANS is not a
// guard.
//
// A test that legitimately needs to write home-derived state calls isolateHome
// and gets its own writable tree.
func TestMain(m *testing.M) {
	os.Exit(runServicesSuite(m))
}

// runServicesSuite exists so the teardown below actually runs: os.Exit in
// TestMain skips deferred calls.
func runServicesSuite(m *testing.M) (code int) {
	dir, err := os.MkdirTemp("", "xkey-gui-services-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gui/services: cannot create the process home: %v\n", err)
		return 1
	}
	defer func() {
		// Restore write permission before removal, or RemoveAll cannot
		// unlink through the directory it is deleting.
		if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil {
			fmt.Fprintf(os.Stderr, "gui/services: cannot restore %s: %v\n", dir, chmodErr)
		}
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			fmt.Fprintf(os.Stderr, "gui/services: cannot remove %s: %v\n", dir, rmErr)
		}
	}()

	processHomeDir = dir
	processConfigDir = filepath.Join(dir, ".config", "xkey")

	// os.UserHomeDir reads $HOME; os.UserConfigDir prefers $XDG_CONFIG_HOME
	// and falls back to $HOME/.config. Both are set so neither resolution
	// path can escape to the real user, whatever the ambient environment.
	for name, value := range map[string]string{
		"HOME":            dir,
		"XDG_CONFIG_HOME": filepath.Join(dir, ".config"),
		"XDG_DATA_HOME":   filepath.Join(dir, ".local", "share"),
		"XDG_CACHE_HOME":  filepath.Join(dir, ".cache"),
		"XDG_STATE_HOME":  filepath.Join(dir, ".local", "state"),
	} {
		if setErr := os.Setenv(name, value); setErr != nil {
			fmt.Fprintf(os.Stderr, "gui/services: cannot set %s: %v\n", name, setErr)
			return 1
		}
	}

	// pkg/config resolves through its own override, not through $HOME, so
	// redirecting the environment alone leaves that resolver pointing at the
	// real directory. This is the second of the two resolvers PR #90 found.
	config.SetConfigDir(processConfigDir)

	if chmodErr := os.Chmod(dir, 0o500); chmodErr != nil {
		fmt.Fprintf(os.Stderr, "gui/services: cannot seal %s: %v\n", dir, chmodErr)
		return 1
	}

	code = m.Run()

	leaked, incomplete := processHomeLeaks()
	if len(leaked) > 0 {
		fmt.Fprintf(os.Stderr,
			"gui/services: %d path(s) were written to the process home, so some test "+
				"reached shared configuration instead of calling isolateHome:\n",
			len(leaked))
		for _, name := range leaked {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		if code == 0 {
			code = 1
		}
	}
	// An inspection that could not be completed is not an inspection that found
	// nothing. Failing here is the whole point of the guard: the alternative is
	// a run that reports success while the evidence for that success was never
	// gathered.
	if len(incomplete) > 0 {
		fmt.Fprintf(os.Stderr,
			"gui/services: the process home could not be fully inspected (%d error(s)), "+
				"so this run says NOTHING about whether a test wrote there:\n",
			len(incomplete))
		for _, err := range incomplete {
			fmt.Fprintf(os.Stderr, "  %v\n", err)
		}
		if code == 0 {
			code = 1
		}
	}
	return code
}

// processHomeLeaks lists everything found under the process home, relative to
// it, and separately reports every reason the inspection was INCOMPLETE. On a
// correct run both are empty: the directory is created empty, no test is
// allowed to write there, and nothing obstructs the walk.
//
// This is the half of the guard that holds under root. The mode bits refuse
// the write outright for an ordinary user, which reports the offending test by
// name at the moment it happens; for uid 0 they refuse nothing, and without
// this the suite would pass on CI having quietly reintroduced the shared state
// the mode bits prevent locally.
//
// The second return value exists because the first version swallowed every
// error -- the per-entry callback error, filepath.WalkDir's own, and
// filepath.Rel's -- and returned "no leaks" for a subtree it had never managed
// to read. A detector that reports success when it could not look is worse
// than no detector: it converts "unknown" into "clean" at exactly the moment
// the answer matters. Traversal continues past a failed entry so one
// unreadable directory does not hide the rest of the tree, but the failure is
// carried out and the suite fails on it.
func processHomeLeaks() (leaked []string, incomplete []error) {
	walkErr := filepath.WalkDir(processHomeDir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			incomplete = append(incomplete, err)
			// Keep walking: the siblings of an unreadable entry are still worth
			// inspecting, and the failure is already recorded above.
			return nil //nolint:nilerr // recorded in incomplete, not swallowed
		}
		if path == processHomeDir {
			return nil
		}
		rel, relErr := filepath.Rel(processHomeDir, path)
		if relErr != nil {
			// Report the leak under its absolute path rather than dropping it.
			// Failing to name a path prettily is no reason to stop naming it.
			incomplete = append(incomplete, relErr)
			rel = path
		}
		leaked = append(leaked, rel)
		return nil
	})
	if walkErr != nil {
		incomplete = append(incomplete, walkErr)
	}
	return leaked, incomplete
}

// isolateHome gives t its own writable home directory and returns its path.
//
// Every home-derived path resolves under it for the duration of the test:
// $HOME and the XDG bases through t.Setenv, and pkg/config through its
// override, which is restored to the sealed process directory on cleanup.
// SOFTHSM2_CONF is claimed too, because PKCS11Service.ensureSoftHSM2Config
// sets it in PRODUCTION code — a global mutation that otherwise outlives the
// test that triggered it and changes what the next one exercises.
//
// t.Setenv panics in a parallel test, which is the intended guard rather than
// a limitation: process-wide environment cannot isolate tests that run at the
// same time, so a test needing this helper cannot be made parallel by
// accident.
func isolateHome(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, ".local", "share"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, ".cache"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, ".local", "state"))
	t.Setenv("SOFTHSM2_CONF", "")

	cfgDir := filepath.Join(dir, ".config", "xkey")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("isolateHome: cannot create %s: %v", cfgDir, err)
	}
	config.SetConfigDir(cfgDir)
	t.Cleanup(func() { config.SetConfigDir(processConfigDir) })

	return dir
}

// TestProcessHomeLeaks_ReportsATraversalItCouldNotComplete pins that the leak
// detector fails CLOSED.
//
// The first version discarded every error the walk could produce and returned
// an empty leak list for a subtree it had never read, so a run that could not
// look reported the same result as a run that looked and found nothing. That
// is the failure mode the detector exists to prevent, reproduced inside the
// detector: TestMain would exit 0 having verified nothing.
//
// The unreadable case is a path that does not exist rather than one made
// unreadable with chmod, and that choice is the point: CI runs this package as
// root, and root traverses a 0000 directory without complaint, so a
// permission-based fixture would prove nothing there. Nothing stats a path
// that is not there, whatever the uid.
func TestProcessHomeLeaks_ReportsATraversalItCouldNotComplete(t *testing.T) {
	restore := processHomeDir
	t.Cleanup(func() { processHomeDir = restore })

	processHomeDir = filepath.Join(t.TempDir(), "was-never-created")

	leaked, incomplete := processHomeLeaks()
	require.Empty(t, leaked, "nothing can be found under a directory that does not exist")
	require.NotEmpty(t, incomplete,
		"a traversal that could not run must be REPORTED, not rendered as a clean result")
}

// TestProcessHomeLeaks_FindsWhatWasWrittenAndReportsNoError is the other half.
//
// Without it the test above passes against a detector that reports an error for
// every input, or one that never finds a leak at all — both of which would make
// the guard useless in the opposite direction.
func TestProcessHomeLeaks_FindsWhatWasWrittenAndReportsNoError(t *testing.T) {
	restore := processHomeDir
	t.Cleanup(func() { processHomeDir = restore })

	dir := t.TempDir()
	processHomeDir = dir

	leaked, incomplete := processHomeLeaks()
	require.Empty(t, leaked, "an empty process home is the correct-run case")
	require.Empty(t, incomplete, "and a readable one produces no traversal errors")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".config", "xkey"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".config", "xkey", "xkey.yaml"), []byte("leaked\n"), 0o600))

	leaked, incomplete = processHomeLeaks()
	require.Empty(t, incomplete)
	require.Contains(t, leaked, filepath.Join(".config", "xkey", "xkey.yaml"),
		"the detector must name the leaked file by its path relative to the process home")
}
