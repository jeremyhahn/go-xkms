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

package manager

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withProbePathsForThisPlatform temporarily replaces the module search list for
// the running platform so probing can be exercised against a controlled
// temporary directory instead of whatever happens to be installed on the host.
// The original table is restored before the test returns.
func withProbePathsForThisPlatform(t *testing.T, paths []string) {
	t.Helper()

	original, had := CommonModulePaths[runtime.GOOS]
	t.Cleanup(func() {
		if had {
			CommonModulePaths[runtime.GOOS] = original
			return
		}
		delete(CommonModulePaths, runtime.GOOS)
	})

	if paths == nil {
		delete(CommonModulePaths, runtime.GOOS)
		return
	}
	CommonModulePaths[runtime.GOOS] = paths
}

// TestProbeModulePaths_UnsupportedPlatform verifies probing on a platform with
// no known module locations returns nil instead of panicking on the missing map
// entry. Go builds for platforms outside the three tabulated ones (freebsd,
// openbsd, ...) reach exactly this path at startup.
func TestProbeModulePaths_UnsupportedPlatform(t *testing.T) {
	withProbePathsForThisPlatform(t, nil)

	assert.Nil(t, ProbeModulePaths())
	assert.Nil(t, ProbeModulesWithNames())
}

// TestProbeModulePaths_ReturnsOnlyExistingFiles verifies the probe filters the
// candidate list down to entries that actually exist and are regular files.
// Returning a path that does not exist would make the caller attempt a dlopen
// that fails much later with an opaque error.
func TestProbeModulePaths_ReturnsOnlyExistingFiles(t *testing.T) {
	dir := t.TempDir()

	present := filepath.Join(dir, "libsofthsm2.so")
	require.NoError(t, os.WriteFile(present, []byte("not a real library"), 0o600))

	missing := filepath.Join(dir, "libykcs11.so")

	// A directory named like a module must not be reported as a module.
	dirNamedLikeModule := filepath.Join(dir, "libopensc.so")
	require.NoError(t, os.Mkdir(dirNamedLikeModule, 0o750))

	withProbePathsForThisPlatform(t, []string{present, missing, dirNamedLikeModule})

	assert.Equal(t, []string{present}, ProbeModulePaths())
}

// TestProbeModulesWithNames_AttachesFriendlyNames verifies the probe pairs each
// discovered path with the human-readable name shown in the module picker.
func TestProbeModulesWithNames_AttachesFriendlyNames(t *testing.T) {
	dir := t.TempDir()

	softhsm := filepath.Join(dir, "libsofthsm2.so")
	yubikey := filepath.Join(dir, "libykcs11.so")
	unknown := filepath.Join(dir, "libvendortoken.so")
	for _, p := range []string{softhsm, yubikey, unknown} {
		require.NoError(t, os.WriteFile(p, []byte("not a real library"), 0o600))
	}

	withProbePathsForThisPlatform(t, []string{softhsm, yubikey, unknown})

	got := ProbeModulesWithNames()
	require.Len(t, got, 3)

	assert.Equal(t, ModuleProbe{LibraryPath: softhsm, DisplayName: "SoftHSM2"}, got[0])
	assert.Equal(t, ModuleProbe{LibraryPath: yubikey, DisplayName: "YubiKey"}, got[1])
	assert.Equal(t, ModuleProbe{LibraryPath: unknown, DisplayName: "vendortoken"},
		got[2], "an unrecognised module keeps its stripped basename")
}

// TestProbeModulesWithNames_EmptyWhenNothingInstalled verifies a host with no
// PKCS#11 modules yields no probes rather than a slice of unusable paths.
func TestProbeModulesWithNames_EmptyWhenNothingInstalled(t *testing.T) {
	withProbePathsForThisPlatform(t, []string{
		filepath.Join(t.TempDir(), "definitely-absent.so"),
	})

	assert.Empty(t, ProbeModulePaths())
	assert.Empty(t, ProbeModulesWithNames())
}
