// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// navRequiresPattern matches every `requires: { resource: "...", action:
// "..." }` RBAC gate in web/app/src/lib/nav.ts. It tolerates the property
// order and whitespace TypeScript/Prettier use in that file, but not a
// structural rewrite of the gate — a rewritten shape is meant to break this
// test rather than silently stop being checked.
var navRequiresPattern = regexp.MustCompile(
	`requires:\s*\{\s*resource:\s*"([a-z_]+)"\s*,\s*action:\s*"([a-z_-]+)"\s*\}`,
)

// canCallPattern matches a literal `can("resource", "action")` /
// `can('resource', 'action')` gate anywhere under web/app/src — the
// component-level counterpart to nav.ts's `requires` gates. It only matches
// string-literal arguments, so `can(item.requires.resource, ...)`
// (Sidebar.svelte's dynamic dispatch over nav.ts) never double-counts what
// navRequiresPairs already extracts from nav.ts itself.
var canCallPattern = regexp.MustCompile(
	`\bcan\(\s*['"]([a-z_]+)['"]\s*,\s*['"]([a-z_-]+)['"]\s*\)`,
)

// webSrcPath resolves web/app/src relative to this source file, so the test
// finds it regardless of the working directory `go test` is invoked from.
func webSrcPath(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed to resolve this test file's path")

	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "web", "app", "src")
	path, err := filepath.Abs(path)
	require.NoError(t, err)
	return path
}

// isWebTestFile reports whether path is a test file rather than application
// source, so the scan below covers only the code that actually ships.
func isWebTestFile(path string) bool {
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".test.svelte") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".spec.svelte")
}

// navRequiresPairs extracts every requires{resource,action} gate declared in
// nav.ts.
func navRequiresPairs(t *testing.T) [][2]string {
	t.Helper()

	path := filepath.Join(webSrcPath(t), "lib", "nav.ts")
	src, err := os.ReadFile(path)
	require.NoError(t, err, "reading %s", path)

	matches := navRequiresPattern.FindAllStringSubmatch(string(src), -1)
	require.NotEmpty(t, matches, "no requires{} gates found in %s; the extraction regex may be stale", path)

	pairs := make([][2]string, 0, len(matches))
	for _, m := range matches {
		pairs = append(pairs, [2]string{m[1], m[2]})
	}
	return pairs
}

// canCallSite pairs an extracted resource:action gate with the file it came
// from, for readable failure messages.
type canCallSite struct {
	pair [2]string
	file string
}

// canCallPairs walks every .svelte and .ts file under web/app/src, excluding
// test files, and extracts every literal can("resource", "action") gate.
func canCallPairs(t *testing.T) []canCallSite {
	t.Helper()

	root := webSrcPath(t)
	var sites []canCallSite

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err, "walking %s", root)
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".svelte") && !strings.HasSuffix(path, ".ts") {
			return nil
		}
		if isWebTestFile(path) {
			return nil
		}

		src, err := os.ReadFile(path)
		require.NoError(t, err, "reading %s", path)

		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)

		for _, m := range canCallPattern.FindAllStringSubmatch(string(src), -1) {
			sites = append(sites, canCallSite{pair: [2]string{m[1], m[2]}, file: rel})
		}
		return nil
	})
	require.NoError(t, err, "walking %s", root)
	require.NotEmpty(t, sites, "no can(\"resource\", \"action\") gates found under %s; the extraction regex may be stale", root)

	return sites
}

// TestUIPermissionMatrix_CoversNavRequires proves every RBAC gate the sidebar
// declares in nav.ts has a matching entry in uiPermissionMatrix. A pair
// present in nav.ts but absent here means /api/v1/auth/me never reports the
// key, so session.svelte.ts's can() is permanently false and the nav entry
// stays hidden even for an identity that holds the grant (go-xkms#846).
func TestUIPermissionMatrix_CoversNavRequires(t *testing.T) {
	matrixSet := make(map[[2]string]bool, len(uiPermissionMatrix))
	for _, pair := range uiPermissionMatrix {
		matrixSet[pair] = true
	}

	for _, pair := range navRequiresPairs(t) {
		t.Run(fmt.Sprintf("%s:%s", pair[0], pair[1]), func(t *testing.T) {
			require.True(t, matrixSet[pair],
				"nav.ts gates on %s:%s but uiPermissionMatrix has no matching entry", pair[0], pair[1])
		})
	}
}

// TestUIPermissionMatrix_CoversCanCalls proves every literal can("resource",
// "action") gate anywhere under web/app/src (button visibility, route
// guards, etc., not just the sidebar) has a matching entry in
// uiPermissionMatrix. A gate present in the UI but absent here means
// /api/v1/auth/me never reports the key, so the control stays hidden even
// for an identity that holds the grant (go-xkms#846).
func TestUIPermissionMatrix_CoversCanCalls(t *testing.T) {
	matrixSet := make(map[[2]string]bool, len(uiPermissionMatrix))
	for _, pair := range uiPermissionMatrix {
		matrixSet[pair] = true
	}

	seen := make(map[[2]string]bool)
	for _, site := range canCallPairs(t) {
		if seen[site.pair] {
			continue
		}
		seen[site.pair] = true

		t.Run(fmt.Sprintf("%s:%s", site.pair[0], site.pair[1]), func(t *testing.T) {
			require.True(t, matrixSet[site.pair],
				"%s calls can(%q, %q) but uiPermissionMatrix has no matching entry",
				site.file, site.pair[0], site.pair[1])
		})
	}
}
